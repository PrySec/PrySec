using System;
using System.IO;
using System.Runtime.CompilerServices;
using PrySec.Core.HwPrimitives;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;

namespace PrySec.Core.IO;

public unsafe class AsciiStream : IDisposable
{
    private bool disposedValue;

    private Stream? _inner;

    private readonly byte* _bufferStart;

    private byte* _currentPosition;

    private readonly Size_T _bufferSize;

    private Size_T _currentSize;

    public AsciiStream(Size_T bufferSize, Stream? inner = null)
    {
        _inner = inner;
        _bufferSize = bufferSize;
        _bufferStart = (byte*)MemoryManager.Malloc(_bufferSize);
    }

    public void Reset(Stream newInner)
    {
        ThrowIfDisposed();
        _inner = newInner;
        _currentSize = 0;
    }

    /// <summary>
    /// Reads a line from the stream and stores it into the <paramref name="output"/> buffer. It stops when either the 
    /// <paramref name="output"/> buffer is full, the newline character is read, or the end-of-file is reached, whichever comes first.
    /// The newline character will not be included in the output, so zero-length reads are possible for empty lines.
    /// </summary>
    /// <param name="output"></param>
    /// <returns>The number of bytes read or <c>-1</c> if the end of file was reached and nothing was read.</returns>
    public int ReadLine(Span<byte> output)
    {
        ThrowIfDisposed();

        int outputOffset = 0;
        do
        {
            if (_currentSize == 0)
            {
                _currentPosition = _bufferStart;
                Span<byte> buffer = new(_bufferStart, _bufferSize);
                int bytesWritten = _inner!.Read(buffer);
                _currentSize = bytesWritten;
                if (bytesWritten <= 0)
                {
                    if (outputOffset == 0)
                    {
                        // reached EOF, no line written
                        return -1;
                    }
                    // could be an empty line. 0 is valid
                    return outputOffset;
                }
            }
            int maxSliceLength = FastMath.Min(_currentSize, output.Length - outputOffset);
            bool foundLf = SliceUntilNewLine(_currentPosition, maxSliceLength, out Span<byte> line);
            // store result
            line.CopyTo(output[outputOffset..]);
            outputOffset += line.Length;
            int removeLfAdditionalOffset = foundLf ? 1 : 0;
            int bytesRead = line.Length + removeLfAdditionalOffset;
            _currentPosition += bytesRead;
            Size_T remainingSize = _currentSize - bytesRead;
            _currentSize = remainingSize;

            if (foundLf || outputOffset >= output.Length)
            {
                // request satisfied
                return outputOffset;
            }
        } while (true);
    }

    /// <summary>
    /// Slices the input ASCII string until a new line is found. Or returns the whole input as a span if EOF is encountered first.
    /// </summary>
    /// <returns><see langword="true"/> if a new line was found. Otherwise <see langword="false"/>.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)] // only used in one place
    private static bool SliceUntilNewLine(byte* input, Size_T inputLength, out Span<byte> slice)
    {
        const ulong LF_MASK_64 = 0x0A0A0A0A_0A0A0A0AuL;
        const uint LF_MASK_32 = 0x0A0A0A0Au;
        const ushort LF_MASK_16 = 0x0A0A;
        const byte LF_MASK_8 = 0x0A;

        int offset = 0;

        ulong* iterator8 = (ulong*)input;
        ulong zeroMask8 = 0uL;

        // 64 bit
        // we perform an 8-byte XOR with the line-feed mask and then check if any byte is 0 (if there was a LF in the block)
        // then we determine the offset of the 0-byte in the block and return.
        for ( ; offset + 8 <= inputLength && zeroMask8 == 0uL; offset += 8, iterator8++)
        {
            // we want to find the first LF in network byte order
            ulong u8 = BinaryUtils.ReadUInt64BigEndian(iterator8) ^ LF_MASK_64;
            zeroMask8 = BinaryUtils.MaskZeroByte(u8);
        }
        if (zeroMask8 != 0uL)
        {
            int idx = 0;
            // the leading bit of the zero byte will be 1 in zeroMask8
            // find the first 1 bit, devide by 8 to get the byte index and reverse everything 
            // to get the offset from the highest byte (network byte order)
            BinaryUtils.BitScanReverse(&idx, zeroMask8);
            int networkOrderByteOffset = 7 - (idx / 8);
            offset += networkOrderByteOffset - 8;
            slice = new Span<byte>(input, offset);
            return true;
        }

        // handle any remaining data below (7 bytes or less)

        // 32 bit
        uint* iterator4 = (uint*)iterator8;
        if (offset + 4 <= inputLength)
        {
            uint u4 = BinaryUtils.ReadUInt32BigEndian(iterator4) ^ LF_MASK_32;
            uint zeroMask4 = BinaryUtils.MaskZeroByte(u4);
            if (zeroMask4 != 0u)
            {
                int idx = 0;
                BinaryUtils.BitScanReverse(&idx, zeroMask4);
                int networkOrderByteOffset = 3 - (idx / 8);
                offset += networkOrderByteOffset;
                slice = new Span<byte>(input, offset);
                return true;
            }
            offset += 4;
            iterator4++;
        }

        // 16 bit
        ushort* iterator2 = (ushort*)iterator4;
        if (offset + 2 <= inputLength)
        {
            ushort u2 = (ushort)(BinaryUtils.ReadUInt16BigEndian(iterator2) ^ LF_MASK_16);
            ushort zeroMask2 = BinaryUtils.MaskZeroByte(u2);
            if (zeroMask2 != 0)
            {
                int idx = 0;
                // scans 32-bit from MSB, so shift 16 bit to fill MSB
                BinaryUtils.BitScanReverse(&idx, (uint)zeroMask2 << 16);
                int networkOrderByteOffset = 3 - (idx / 8);
                offset += networkOrderByteOffset;
                slice = new Span<byte>(input, offset);
                return true;    
            }
            offset += 2;
            iterator2++;
        }

        // 8 bit
        if (offset + 1 <= inputLength)
        {
            byte* iterator = (byte*)iterator2;
            if (*iterator == LF_MASK_8)
            {
                slice = new Span<byte>(input, offset);
                return true;
            }
            offset++;
        }

        slice = new Span<byte>(input, offset);
        return false;
    }

    private void ThrowIfDisposed()
    {
        if (disposedValue)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            MemoryManager.Free(_bufferStart);
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