using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashs
{
    public unsafe abstract class Sha2UInt32Scp : ShaUInt32Scp
    {
        private protected const int DIGEST_DWORD_LENGTH = 8;

        /// <summary>
        /// The length in bytes of the final Sha 256 digest
        /// </summary>
        private protected const int DIGEST_LENGTH = DIGEST_DWORD_LENGTH * sizeof(uint);

        /// <summary>
        /// The length of the message schedule array in 32-bit words.
        /// </summary>
        private protected const int MESSAGE_SCHEDULE_BUFFER_LENGTH = 64;

        private protected const int BLOCK_SIZE = 16 * sizeof(uint);

        private protected readonly uint[] H;

        private static readonly uint[] K = new uint[] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

        private protected Sha2UInt32Scp(uint[] initial)
        {
            H = initial;
        }

        private protected DeterministicSpan<uint> HashCoreHelper(ref ShaScpState<uint> state, uint* messageScheduleBuffer)
        {
            // create a buffer to hold the result
            DeterministicSpan<uint> resultBuffer = new(DIGEST_DWORD_LENGTH);

            // initialize result hash
            fixed (uint* pInitialHash = H)
            {
                Unsafe.CopyBlockUnaligned(resultBuffer.BasePointer, pInitialHash, DIGEST_LENGTH);
            }

            uint a, b, c, d, e, f, g, h;
            int j;

            // Process the message in successive 512 - bit chunks (64 byte blocks / 16 uint blocks)
            for (int i = 0; i < state.BlockCount; i++)
            {
                // copy current chunk (64 bytes) into first 16 words w[0..15] of the message schedule array
                Unsafe.CopyBlockUnaligned(messageScheduleBuffer, state.Buffer.BasePointer + (i << 4), BLOCK_SIZE);

                // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
                for (j = 16; j < MESSAGE_SCHEDULE_BUFFER_LENGTH; j++)
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
                a = resultBuffer.BasePointer[0];
                b = resultBuffer.BasePointer[1];
                c = resultBuffer.BasePointer[2];
                d = resultBuffer.BasePointer[3];
                e = resultBuffer.BasePointer[4];
                f = resultBuffer.BasePointer[5];
                g = resultBuffer.BasePointer[6];
                h = resultBuffer.BasePointer[7];

                // Compression function main loop
                for (j = 0; j < MESSAGE_SCHEDULE_BUFFER_LENGTH; j++)
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
            return resultBuffer;
        }
    }
}
