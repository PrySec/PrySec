using PrySec.Base.Memory;
using PrySec.Base.Primitives;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashs
{
    /// <summary>
    /// SHA-256 Secure Crypto Provider
    /// </summary>
    public static unsafe class Sha256Scp
    {
        /// <summary>
        /// The length in bytes of the final Sha 256 digest
        /// </summary>
        private const int DIGEST_LENGTH = 32;

        /// <summary>
        /// The length of the message schedule array in 32-bit words.
        /// </summary>
        private const int MESSAGE_SCHEDULE_BUFFER_LENGTH = 64;

        private static readonly uint[] H = new uint[] {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

        private static readonly uint[] K = new uint[] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

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

            // create a 64-entry message schedule array w[0..63] of 32-bit words
            uint* messageScheduleBuffer = stackalloc uint[MESSAGE_SCHEDULE_BUFFER_LENGTH];

            // create a buffer to hold the result
            DeterministicSpan<uint> resultBuffer = new(8);
            fixed (uint* pInitialHash = H)
            {
                Unsafe.CopyBlockUnaligned(resultBuffer.BasePointer, pInitialHash, DIGEST_LENGTH);
            }

            // Process the message in successive 512 - bit chunks (64 byte blocks / 16 uint blocks)
            for (int i = 0; i < blockCount; i++)
            {
                // copy current chunk (64 bytes) into first 16 words w[0..15] of the message schedule array
                Unsafe.CopyBlockUnaligned(messageScheduleBuffer, buffer.BasePointer + (i << 4), 64);

                // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
                for (int j = 16; j < 64; j++)
                {
                    uint s0In = messageScheduleBuffer[j - 15];
                    uint s1In = messageScheduleBuffer[j - 2];

                    // s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
                    uint s0 = ((s0In >> 7) | (s0In << 25)) ^ ((s0In >> 18) | (s0In << 14)) ^ (s0In >> 3);

                    // s1 := (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
                    uint s1 = ((s1In >> 17) | (s1In << 15)) ^ ((s1In >> 19) | (s1In << 13)) ^ (s1In >> 10);

                    // w[i] := w[i-16] + s0 + w[i-7] + s1
                    messageScheduleBuffer[j] = messageScheduleBuffer[j - 16] + s0 + messageScheduleBuffer[j - 7] + s1;
                }

                // initialize working variables
                uint a = resultBuffer.BasePointer[0];
                uint b = resultBuffer.BasePointer[1];
                uint c = resultBuffer.BasePointer[2];
                uint d = resultBuffer.BasePointer[3];
                uint e = resultBuffer.BasePointer[4];
                uint f = resultBuffer.BasePointer[5];
                uint g = resultBuffer.BasePointer[6];
                uint h = resultBuffer.BasePointer[7];

                // Compression function main loop
                for (int j = 0; j < 64; j++)
                {
                    // S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
                    uint s1 = ((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7));
                    // ch:= (e and f) xor((not e) and g)
                    uint ch = (e & f) ^ ((~e) & g);
                    // temp1:= h + S1 + ch + k[i] + w[i]
                    uint temp1 = unchecked(h + s1 + ch + K[j] + messageScheduleBuffer[j]);
                    // S0:= (a rightrotate 2) xor(a rightrotate 13) xor(a rightrotate 22)
                    uint s0 = ((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10));
                    // maj:= (a and b) xor(a and c) xor(b and c)
                    uint maj = (a & b) ^ (a & c) ^ (b & c);
                    // temp2:= S0 + maj
                    uint temp2 = s0 + maj;

                    h = g;
                    g = f;
                    f = e;
                    e = d + temp1;
                    d = c;
                    c = b;
                    b = a;
                    a = temp1 + temp2;
                }
                unchecked
                {
                    // Add the compressed chunk to the current hash value
                    resultBuffer.BasePointer[0] += a;
                    resultBuffer.BasePointer[1] += b;
                    resultBuffer.BasePointer[2] += c;
                    resultBuffer.BasePointer[3] += d;
                    resultBuffer.BasePointer[4] += e;
                    resultBuffer.BasePointer[5] += f;
                    resultBuffer.BasePointer[6] += g;
                    resultBuffer.BasePointer[7] += h;
                }
            }

            // Zero used stack memory
            new Span<uint>(messageScheduleBuffer, MESSAGE_SCHEDULE_BUFFER_LENGTH).Fill(0x0);

            // Fix endianness
            for (int i = 0; i < 8; i++)
            {
                resultBuffer.BasePointer[i] = (UInt32BE)resultBuffer.BasePointer[i];
            }
            return resultBuffer.CastAs<byte>();
        }
    }
}