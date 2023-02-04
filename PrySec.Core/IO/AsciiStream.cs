using System;
using System.IO;
using PrySec.Core.HwPrimitives;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;

namespace PrySec.Core.IO;

public unsafe class AsciiStream : IDisposable
{
    private bool disposedValue;

    private readonly Stream _inner;

    private readonly byte* _buffer;

    private readonly Size_T _bufferSize;

    private Size_T _currentOffset;

    public AsciiStream(Stream inner, Size_T bufferSize)
    {
        _inner = inner;
        _bufferSize = bufferSize;
        _buffer = (byte*)MemoryManager.Malloc(_bufferSize);
    }



    public int ReadLine(Stream stream, Span<byte> output)
    {
        Span<byte> buffer = new(_buffer, _bufferSize);
        if (output.Length <= _currentOffset)
        {
            // satisfy request from cache
            Span<byte> outData = buffer[..output.Length];
            outData.CopyTo(output);
            Span<byte> remainingCache = buffer[outData.Length..(int)_currentOffset];
            remainingCache.CopyTo(buffer);
            _currentOffset = remainingCache.Length;
            return output.Length;
        }
        // require more data than is available in cache
        do
        {
            // fill cache (don't override cached data)
            Span<byte> freeSpace = buffer[(int)_currentOffset..];
            int bytesRead = stream.Read(freeSpace);
        } while (true);
    }

    // TODO: SIMD-ify
    // TODO: use pointers
    private static bool SliceUntilNewLine(byte* input, Size_T inputLength, out Span<byte> slice)
    {
        const ulong LF_MASK_64 = 0x0A0A0A0A_0A0A0A0AuL;
        const uint LF_MASK_32 = 0x0A0A0A0Au;
        const ushort LF_MASK_16 = 0x0A0A;
        const byte LF_MASK_8 = 0x0A;

        ulong* iterator8 = (ulong*)input;

        int offset = 0;
        ulong zeroMask8 = 0uL;

        ulong u8;
        for ( ; offset + 8 < inputLength && zeroMask8 == 0uL; offset += 8, iterator8++)
        {
            u8 = BinaryUtils.ReadUInt64BigEndian(iterator8) ^ LF_MASK_64;
            zeroMask8 = BinaryUtils.MaskZeroByte(u8);
        }
        if (zeroMask8 != 0uL)
        {
            int idx = 0;
            BinaryUtils.BitScanReverse(&idx, zeroMask8);
            int networkOrderByteOffset = 7 - (idx / 8);

        }
        slice = default;
        return false;
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            MemoryManager.Free(_buffer);
            disposedValue = true;
        }
    }

    ~AsciiStream()
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