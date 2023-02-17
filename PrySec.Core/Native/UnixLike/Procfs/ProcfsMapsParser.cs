using System;
using System.IO;
using System.Runtime.CompilerServices;
using PrySec.Core.HwPrimitives;
using PrySec.Core.IO;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives.Converters;

namespace PrySec.Core.Native.UnixLike.Procfs;

public unsafe class ProcfsMapsParser : IDisposable
{
    private bool disposedValue;

    private const int PATH_MAX = 4096;

    private const int PROCMAPS_LINE_MAX_LENGTH = PATH_MAX + 100;

    private readonly AsciiStream _stream;

    private readonly byte* _buffer;

    public ProcfsMapsParser(Size_T expectedAvgLineLength)
    {
        _stream = new AsciiStream(expectedAvgLineLength);
        _buffer = (byte*)MemoryManager.Malloc(PROCMAPS_LINE_MAX_LENGTH);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ProcfsMemoryRegionInfoList VirtualQueryEx(string procfsMapsPath)
    {
        using Stream procfsStream = File.OpenRead(procfsMapsPath);
        return VirtualQueryCore(procfsStream);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ProcfsMemoryRegionInfoList VirtualQueryEx(int pid) =>
        VirtualQueryEx($"/proc/{pid}/maps");

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ProcfsMemoryRegionInfoList VirtualQuery() =>
        VirtualQueryEx("/proc/self/maps");

    private ProcfsMemoryRegionInfoList VirtualQueryCore(Stream procfsStream)
    {
        ProcfsMemoryRegionInfoList procfsInfo = new();
        _stream.Reset(procfsStream);
        Span<byte> buf = new(_buffer, PROCMAPS_LINE_MAX_LENGTH);
        int bytesRead;

        while ((bytesRead = _stream.ReadLine(buf)) != -1)
        {
            ProcfsMemoryRegionInfo* pInfo = (ProcfsMemoryRegionInfo*)MemoryManager.Malloc(sizeof(ProcfsMemoryRegionInfo));
            ParseLine(_buffer, bytesRead, pInfo, default, true);
            procfsInfo.Add(pInfo);
        }
        return procfsInfo;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ProcfsMemoryRegionInfo* VirtualQueryEx(string procfsMapsPath, nint address, bool allocatePath = true)
    {
        using Stream procfsStream = File.OpenRead(procfsMapsPath);
        return VirtualQueryCore(procfsStream, address, allocatePath);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ProcfsMemoryRegionInfo* VirtualQueryEx(int pid, nint address, bool allocatePath = true) =>
        VirtualQueryEx($"/proc/{pid}/maps", address, allocatePath);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ProcfsMemoryRegionInfo* VirtualQuery(nint address, bool allocatePath = true) =>
        VirtualQueryEx("/proc/self/maps", address, allocatePath);

    private ProcfsMemoryRegionInfo* VirtualQueryCore(Stream procfsStream, nint address, bool allocatePath = true)
    {
        ProcfsMemoryRegionInfo* pInfo = (ProcfsMemoryRegionInfo*)MemoryManager.Malloc(sizeof(ProcfsMemoryRegionInfo));
        if (!TryVirtualQueryCore(procfsStream, address, pInfo, allocatePath))
        {
            MemoryManager.Free(pInfo);
            return null;
        }
        return pInfo;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryVirtualQueryEx(string procfsMapsPath, nint address, ProcfsMemoryRegionInfo* pInfo, bool allocatePath = true)
    {
        using Stream procfsStream = File.OpenRead(procfsMapsPath);
        return TryVirtualQueryCore(procfsStream, address, pInfo, allocatePath);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryVirtualQueryEx(int pid, nint address, ProcfsMemoryRegionInfo* pInfo, bool allocatePath = true) =>
        TryVirtualQueryEx($"/proc/{pid}/maps", address, pInfo, allocatePath);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool TryVirtualQuery(nint address, ProcfsMemoryRegionInfo* pInfo, bool allocatePath = true) =>
        TryVirtualQueryEx("/proc/self/maps", address, pInfo, allocatePath);

    private bool TryVirtualQueryCore(Stream procfsStream, nint address, ProcfsMemoryRegionInfo* pInfo, bool includePath)
    {
        _stream.Reset(procfsStream);
        Span<byte> buf = new(_buffer, PROCMAPS_LINE_MAX_LENGTH);
        int bytesRead;

        while ((bytesRead = _stream.ReadLine(buf)) != -1)
        {
            if (ParseLine(_buffer, bytesRead, pInfo, address, includePath))
            {
                return true;
            }
        }
        return false;
    }

    private static bool ParseLine(byte* line, Size_T size, ProcfsMemoryRegionInfo* pInfo, nint searchAddress, bool includePath)
    {
        byte* start = line;
        byte* current = line;
        Size_T count = 0;

        // addr1
        for (; size > 0 && *current != '-'; size--, current++, count++) { }

        // in-place hex-decode
        int offset = sizeof(ulong) - (count / 2);
        ulong addressMask = (~0uL) >>> (offset * 8);
        HexConverter.Unhexlify(start, count, start + offset, count);
        nint startAddress = (nint)(BinaryUtils.ReadUInt64BigEndian((ulong*)start) & addressMask);
        if (searchAddress != default && startAddress != searchAddress)
        {
            return false;
        }
        pInfo->RegionStartAddress = startAddress;

        // skip '-'
        current++;
        size--;

        // addr2
        HexConverter.Unhexlify(current, count, start + offset, count);
        nint endAddress = (nint)(BinaryUtils.ReadUInt64BigEndian((ulong*)start) & addressMask);
        pInfo->RegionEndAddress = endAddress;
        current += count;
        size -= count;

        // size
        pInfo->RegionSize = (Size_T)(endAddress - startAddress);

        SkipWhiteSpace(&current, &size);

        // perms
        uint perms = BinaryUtils.ReadUInt32BigEndian((uint*)current);
        pInfo->Permissions = ProcfsPermissionParser.Parse(perms);
        current += sizeof(uint);
        size -= sizeof(uint);

        SkipWhiteSpace(&current, &size);

        // offset
        count = 0;
        start = current;
        for (byte b = *current; size > 0 && b != ' ' && b != '\t'; size--, b = *++current, count++) { }
        offset = sizeof(ulong) - (count / 2);
        ulong offsetMask = (~0uL) >>> (offset * 8);
        HexConverter.Unhexlify(start, count, start + offset, count);
        ulong offsetData = BinaryUtils.ReadUInt64BigEndian((ulong*)start) & offsetMask;
        pInfo->Offset = (nuint)offsetData;

        SkipWhiteSpace(&current, &size);

        // dev
        HexConverter.Unhexlify(current, 2 * sizeof(byte), current, sizeof(byte));
        byte devMajor = *current;
        current += 3; // major + ':'
        size -= 3;
        HexConverter.Unhexlify(current, 2 * sizeof(byte), current, sizeof(byte));
        byte devMinor = *current;
        current += 2;
        size -= 2;
        pInfo->Device = new ProcfsDevice(devMajor, devMinor);

        SkipWhiteSpace(&current, &size);

        // inode
        count = 0;
        start = current;
        for (byte b = *current; size > 0 && b != ' ' && b != '\t'; size--, b = *++current, count++) { }
        ulong inode = BinaryUtils.Strtoull(start, count);
        pInfo->Inode = (nint)inode;

        SkipWhiteSpace(&current, &size);

        // path
        if (includePath && size > 0)
        {
            pInfo->PathLength = size;
            pInfo->Path = (byte*)MemoryManager.Malloc(size);
            MemoryManager.Memcpy(pInfo->Path, current, size);
        }
        else
        {
            pInfo->PathLength = 0;
            pInfo->Path = null;
        }
        return true;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SkipWhiteSpace(byte** pp, Size_T* pSize)
    {
        const byte WS = (byte)' ';
        const byte TAB = (byte)'\t';
        for (byte b = **pp; (b == WS || b == TAB) && *pSize > 0; b = *++*pp, --*pSize) { }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                _stream.Dispose();
            }
            MemoryManager.Free(_buffer);
            disposedValue = true;
        }
    }

    ~ProcfsMapsParser()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}
