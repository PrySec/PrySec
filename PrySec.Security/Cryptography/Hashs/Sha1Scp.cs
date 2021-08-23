using PrySec.Base.Memory;
using PrySec.Base.Primitives;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashs
{
    public static unsafe class Sha1Scp
    {
        private static readonly uint[] H = new uint[DIGEST_DWORD_LENGTH] 
        {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

        private const int DIGEST_DWORD_LENGTH = 5;

        private const int DIGEST_LENGTH = DIGEST_DWORD_LENGTH * sizeof(uint);

        private const int MESSAGE_SCHEDULE_BUFFER_LENGTH = 80;

        public static DeterministicSpan<byte> Digest<T>(IUnmanaged<T> memory) where T : unmanaged
        {
            int dataLength = memory.ByteSize;

            // convert string msg into 512-bit blocks (array of 16 32-bit integers) [§5.2.1]
            // length (in 32-bit integers) of content length + 0x80 byte padding + appended length
            int int32Length = (dataLength >> 2) + 3;

            // number of 16-integer (512-bit) blocks required to hold the data
            // is equivilant to ceil(int32Length / 16d)
            int blockCount = (int32Length >> 4) + (((-(int32Length & 0xF)) >> 31) & 0x1);

            // blockCount * 16;
            int allocatedSize = blockCount << 4;

            using DeterministicSpan<uint> buffer = new(allocatedSize);
            buffer.ZeroMemory();
            using (IMemoryAccess<T> memoryAccess = memory.GetAccess())
            {
                Unsafe.CopyBlockUnaligned(buffer.BasePointer, memoryAccess.Pointer, memoryAccess.ByteSize);
            }

            // append padding
            ((byte*)buffer.BasePointer)[dataLength] = 0x80;

            // calculate length of original message in bits
            // write message length as 64 bit big endian unsigned integer to the end of the buffer
            *(ulong*)(buffer.BasePointer + buffer.Size - 2) = (UInt64BE)(((ulong)dataLength) << 3);

            // convert 32 bit word wise back to little endian.
            for (int i = 0; i < allocatedSize; i++)
            {
                buffer.BasePointer[i] = (UInt32BE)buffer.BasePointer[i];
            }

            // create a 80-entry message schedule array w[0..79] of 32-bit words
            uint* messageScheduleBuffer = stackalloc uint[MESSAGE_SCHEDULE_BUFFER_LENGTH];

            // create a buffer to hold the result
            DeterministicSpan<uint> resultBuffer = new(DIGEST_DWORD_LENGTH);

            // initialize result hash
            fixed (uint* pInitialHash = H)
            {
                Unsafe.CopyBlockUnaligned(resultBuffer.BasePointer, pInitialHash, DIGEST_LENGTH);
            }

            // Process the message in successive 512 - bit chunks (64 byte blocks / 16 uint blocks)
            for (int i = 0; i < blockCount; i++)
            {
                // copy current chunk (64 bytes) into first 16 words w[0..15] of the message schedule array
                Unsafe.CopyBlockUnaligned(messageScheduleBuffer, buffer.BasePointer + (i << 4), 64);

                // Message schedule: extend the sixteen 32-bit words into eighty 32-bit words
                for (int j = 16; j < MESSAGE_SCHEDULE_BUFFER_LENGTH; j++)
                {
                    // w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
                    uint temp = (messageScheduleBuffer[j - 3]
                                ^ messageScheduleBuffer[j - 8]
                                ^ messageScheduleBuffer[j - 14]
                                ^ messageScheduleBuffer[j - 16]);
                    messageScheduleBuffer[j] = (temp << 1) | (temp >> 31);
                }

                // Initialize hash value for this chunk
                uint a = resultBuffer.BasePointer[0];
                uint b = resultBuffer.BasePointer[1];
                uint c = resultBuffer.BasePointer[2];
                uint d = resultBuffer.BasePointer[3];
                uint e = resultBuffer.BasePointer[4];

                // Main compression loop
                for (int j = 0; j < MESSAGE_SCHEDULE_BUFFER_LENGTH; j++)
                {
                    uint f, k;
                    if (j < 20)
                    {
                        f = (b & c) | ((~b) & d);
                        k = 0x5A827999u;
                    }
                    else if (j < 40)
                    {
                        f = b ^ c ^ d;
                        k = 0x6ED9EBA1u;
                    }
                    else if (j < 60)
                    {
                        f = (b & c) | (b & d) | (c & d);
                        k = 0x8F1BBCDCu;
                    }
                    else
                    {
                        f = b ^ c ^ d;
                        k = 0xCA62C1D6u;
                    }

                    uint temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[j]);
                    e = d;
                    d = c;
                    c = (b << 30) | (b >> 2);
                    b = a;
                    a = temp;
                }

                // Add this chunk's hash to result so far
                unchecked
                {
                    resultBuffer.BasePointer[0] += a;
                    resultBuffer.BasePointer[1] += b;
                    resultBuffer.BasePointer[2] += c;
                    resultBuffer.BasePointer[3] += d;
                    resultBuffer.BasePointer[4] += e;
                }
            }

            // Zero used stack memory
            new Span<uint>(messageScheduleBuffer, MESSAGE_SCHEDULE_BUFFER_LENGTH).Fill(0x0);

            // Fix endianness
            for (int i = 0; i < DIGEST_DWORD_LENGTH; i++)
            {
                resultBuffer.BasePointer[i] = (UInt32BE)resultBuffer.BasePointer[i];
            }
            return resultBuffer.CastAs<byte>();
        }
    }
}
