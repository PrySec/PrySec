using System;
using System.Buffers.Binary;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using PrySec.Core.HwPrimitives;
using PrySec.Core.IO;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives.Converters;

namespace PrySec.Core.Native.UnixLike;

public unsafe class ProcfsMapsParser : IDisposable
{
    private bool disposedValue;

    private const int PATH_MAX = 4096;

    private const int PROCMAPS_LINE_MAX_LENGTH = PATH_MAX + 100;

    private readonly AsciiStream _stream;

    private readonly byte* _buffer;

    public ProcfsMapsParser(Size_T bufferSize)
    {
        _stream = new AsciiStream(bufferSize);
        _buffer = (byte*)MemoryManager.Malloc(PROCMAPS_LINE_MAX_LENGTH);
    }

    public ProcfsMemoryRegionInfoList QueryProcfsEx(int pid)
    {
        using Stream procfsStream = File.OpenRead($"/proc/{pid}/maps");
        return QueryProcCore(procfsStream);
    }

    public ProcfsMemoryRegionInfoList QueryProcfs()
    {
        using Stream procfsStream = File.OpenRead("/proc/self/maps");
        return QueryProcCore(procfsStream);
    }

    private ProcfsMemoryRegionInfoList QueryProcCore(Stream procfsStream)
    {
        ProcfsMemoryRegionInfoList procfsInfo = new();
        _stream.Reset(procfsStream);
        Span<byte> buf = new(_buffer, PROCMAPS_LINE_MAX_LENGTH);
        int bytesRead;

        while ((bytesRead = _stream.ReadLine(buf)) != -1)
        {
            ProcfsMemoryRegionInfo* pInfo = (ProcfsMemoryRegionInfo*)MemoryManager.Malloc(sizeof(ProcfsMemoryRegionInfo));
            pInfo->Path = null;
            ParseLine(_buffer, bytesRead, pInfo);
            procfsInfo.Add(pInfo);
        }
        return procfsInfo;
    }

    private static void ParseLine(byte* line, Size_T size, ProcfsMemoryRegionInfo* pInfo)
    {
        // TODO parse...
        Console.WriteLine($"Mock parsing: {Encoding.ASCII.GetString(line, size)}");

        byte* start = line;
        byte* current = line;
        Size_T count = 0;

        // addr1
        for (; size > 0 && *current != '-'; size--, current++, count++)
        {
            Nop();
        }
        // in-place hex-decode
        int offset = (sizeof(ulong) - (count / 2));
        ulong addressMask = (~0uL) >>> (offset * 8);
        HexConverter.Unhexlify(start, count, start + offset, count);
        ulong startAddress = BinaryUtils.ReadUInt64BigEndian((ulong*)start) & addressMask;
        pInfo->RegionStartAddress = (nint)startAddress;

        // addr2
        current++;
        size--;
        HexConverter.Unhexlify(current, count, start + offset, count);
        ulong endAddress = BinaryUtils.ReadUInt64BigEndian((ulong*)start) & addressMask;
        pInfo->RegionEndAddress = (nint)endAddress;
        size -= count;

        // size
        pInfo->RegionSize = (Size_T)(endAddress - startAddress);

        SkipWhiteSpace(&current, &size);

        uint perms = BinaryUtils.ReadUInt32BigEndian((uint*)current);
        System.Console.WriteLine(perms);
        pInfo->Permissions = ProcfsPermissionParser.Parse(perms);
        System.Console.WriteLine(pInfo->Permissions);

        //Console.WriteLine(pInfo->ToString());
    }

    

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SkipWhiteSpace(byte** pp, Size_T* pSize)
    {
        for (byte b = **pp; (b == ' ' || b == '\t') && *pSize > 0; b = *++*pp, ++*pSize)
        {
            Nop();
            System.Console.WriteLine("skip");
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Nop() { }

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

public unsafe class ProcfsMemoryRegionInfoList : IDisposable, IReadOnlyList<UnmanagedReference<ProcfsMemoryRegionInfo>>
{
    private ProcfsMemoryRegionInfoNode* _head;

    private ProcfsMemoryRegionInfoNode* _tail;

    private bool disposedValue;

    public int Count { get; private set; }

#pragma warning disable IDE0011 // Add braces

    public UnmanagedReference<ProcfsMemoryRegionInfo> this[int index] 
    {
        get 
        {
            if (index >= Count)
            {
                throw new IndexOutOfRangeException();
            }
            int i;
            ProcfsMemoryRegionInfoNode* node;
            if (index < Count / 2)
            {
                for (node = _head, i = 0; node != null && i < index; node = node->Next, i++) ;
                return new UnmanagedReference<ProcfsMemoryRegionInfo>(node->Info);
            }
            else
            {
                for (node = _tail, i = Count - 1; node != null && i > index; node = node->Previous, i--) ;
                return new UnmanagedReference<ProcfsMemoryRegionInfo>(node->Info);
            }
        }
    }

#pragma warning restore IDE0011 // Add braces

    internal void Add(ProcfsMemoryRegionInfo* info)
    {
        ProcfsMemoryRegionInfoNode* node = ProcfsMemoryRegionInfoNode.Create(info);
        if (Count == 0)
        {
            _head = node;
            _tail = node;
        }
        else
        {
            node->Previous = _tail;
            _tail->Next = node;
            _tail = node;
            Count++;
        }
    }

    public IEnumerator<UnmanagedReference<ProcfsMemoryRegionInfo>> GetEnumerator() => 
        new ProcfsMemoryRegionInfoListEnumerator(_head);

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                // dispose managed state (managed objects)
            }

            for (ProcfsMemoryRegionInfoNode* node = _head, tmp = null; node != null;)
            {
                tmp = node;
                node = node->Next;
                MemoryManager.Free(tmp->Info);
                MemoryManager.Free(tmp);
            }
            _head = null;
            _tail = null;
            disposedValue = true;
        }
    }

    ~ProcfsMemoryRegionInfoList()
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

internal unsafe class ProcfsMemoryRegionInfoListEnumerator : IEnumerator<UnmanagedReference<ProcfsMemoryRegionInfo>>
{
    private ProcfsMemoryRegionInfoNode* _current = null;
    private readonly ProcfsMemoryRegionInfoNode* _head;
    private bool initialized = false;

    public ProcfsMemoryRegionInfoListEnumerator(ProcfsMemoryRegionInfoNode* head)
    {
        _head = head;
    }

    public UnmanagedReference<ProcfsMemoryRegionInfo> Current => 
        _current != null
            ? new UnmanagedReference<ProcfsMemoryRegionInfo>(_current->Info)
            : new UnmanagedReference<ProcfsMemoryRegionInfo>(null);

    object IEnumerator.Current => Current;

    public void Dispose()
    {
    }

    public bool MoveNext()
    {
        if (!initialized)
        {
            initialized = true;
            _current = _head;
        }
        else
        {
            _current = _current->Next;
        }
        return _current != null;
    }

    public void Reset()
    {
        _current = null;
        initialized = false;
    }
}

internal unsafe struct ProcfsMemoryRegionInfoNode
{
    public ProcfsMemoryRegionInfo* Info;
    public ProcfsMemoryRegionInfoNode* Previous;
    public ProcfsMemoryRegionInfoNode* Next;

    public static ProcfsMemoryRegionInfoNode* Create(ProcfsMemoryRegionInfo* info)
    {
        ProcfsMemoryRegionInfoNode* node = (ProcfsMemoryRegionInfoNode*)MemoryManager.Malloc(sizeof(ProcfsMemoryRegionInfoNode));
        node->Info = info;
        return node;
    }
}

public unsafe struct ProcfsMemoryRegionInfo
{
    public nint RegionStartAddress;
    public nint RegionEndAddress;
    public Size_T RegionSize;
    public ProcfsPermissions Permissions;
    public nuint Offset;
    public ProcfsDevice Device;
    public nint Inode;
    public byte* Path;
    public int PathLength;

    public readonly string? ReadPath() =>
        Path == null 
            ? null 
            : Encoding.ASCII.GetString(Path, PathLength);

    public override readonly string ToString()
    {
        return $"{{0x{RegionStartAddress:x16}-0x{RegionEndAddress:x16} ({RegionSize} bytes) {(Permissions.ToString())} {Offset} {Device} {Inode} {ReadPath() ?? string.Empty}}}";
    }
}

[Flags]
public enum ProcfsPermissions : int
{
    NoAccess = 0x0,
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
    Shared = 0x8,
}

public static class ProcfsPermissionParser
{
    private const uint PERM_READ = 'r' << 24;
    private const uint PERM_WRITE = 'w' << 16;
    private const uint PERM_EXEC = 'x' << 8;
    private const uint PERM_SHRD = 's' << 0;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ProcfsPermissions Parse(uint data) => 
        ProcfsPermissions.NoAccess
        | (ProcfsPermissions)(~((-(int)((data & PERM_READ) ^ PERM_READ)) >> 31) & (int)ProcfsPermissions.Read)
        | (ProcfsPermissions)(~((-(int)((data & PERM_WRITE) ^ PERM_WRITE)) >> 31) & (int)ProcfsPermissions.Write)
        | (ProcfsPermissions)(~((-(int)((data & PERM_EXEC) ^ PERM_EXEC)) >> 31) & (int)ProcfsPermissions.Execute)
        | (ProcfsPermissions)(~((-(int)((data & PERM_SHRD) ^ PERM_SHRD)) >> 31) & (int)ProcfsPermissions.Shared);
}

public readonly struct ProcfsDevice
{
    public readonly byte Major;
    public readonly byte Minor;

    public ProcfsDevice(byte major, byte minor)
    {
        Major = major;
        Minor = minor;
    }
}