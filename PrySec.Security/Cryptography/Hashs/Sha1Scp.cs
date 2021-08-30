using PrySec.Base.Memory;
using PrySec.Security.MemoryProtection.Universal;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashs
{
    public unsafe class Sha1Scp : ShaUInt32Scp
    {
        private const int DIGEST_DWORD_LENGTH = 5;
        private const int DIGEST_LENGTH = DIGEST_DWORD_LENGTH * sizeof(uint);

        private const int MESSAGE_SCHEDULE_BUFFER_LENGTH = 80;

        private static readonly uint[] H = new uint[5]
        {
            0x67452301u,
            0xEFCDAB89u,
            0x98BADCFEu,
            0x10325476u,
            0xC3D2E1F0u
        };

        private protected override DeterministicSpan<byte> HashCore(ref ShaScpState<uint> state)
        {
            // create a 80-entry message schedule array w[0..79] of 32-bit words
            uint* messageScheduleBuffer = stackalloc uint[MESSAGE_SCHEDULE_BUFFER_LENGTH];

            // create a buffer to hold the result
            DeterministicSpan<uint> resultBuffer = new(DIGEST_DWORD_LENGTH);

            // initialize result hash
            fixed (uint* pInitialHash = H)
            {
                Unsafe.CopyBlockUnaligned(resultBuffer.BasePointer, pInitialHash, DIGEST_LENGTH);
            }

            int j;
            uint a, b, c, d, e;

            // Process the message in successive 512 - bit chunks (64 byte blocks / 16 uint blocks)
            for (int i = 0; i < state.BlockCount; i++)
            {
                // copy current chunk (64 bytes) into first 16 words w[0..15] of the message schedule array
                Unsafe.CopyBlockUnaligned(messageScheduleBuffer, state.Buffer.BasePointer + (i << 4), 64);

                // Message schedule: extend the sixteen 32-bit words into eighty 32-bit words
                for (j = 16; j < MESSAGE_SCHEDULE_BUFFER_LENGTH; j++)
                {
                    // w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
                    uint tmp = (messageScheduleBuffer[j - 3]
                                ^ messageScheduleBuffer[j - 8]
                                ^ messageScheduleBuffer[j - 14]
                                ^ messageScheduleBuffer[j - 16]);
                    messageScheduleBuffer[j] = (tmp << 1) | (tmp >> 31);
                }

                // Initialize hash value for this chunk
                a = resultBuffer.BasePointer[0];
                b = resultBuffer.BasePointer[1];
                c = resultBuffer.BasePointer[2];
                d = resultBuffer.BasePointer[3];
                e = resultBuffer.BasePointer[4];

                #region Main compression loop

                /* Round 1 */
                for (j = 0; j < 20; j += 5)
                {
                    e += ((a << 5) | (a >> 27)) + (d ^ (b & (c ^ d))) + messageScheduleBuffer[j] + 0x5a827999;
                    b = (b << 30) | (b >> 2);
                    d += ((e << 5) | (e >> 27)) + (c ^ (a & (b ^ c))) + messageScheduleBuffer[j + 1] + 0x5a827999;
                    a = (a << 30) | (a >> 2);
                    c += ((d << 5) | (d >> 27)) + (b ^ (e & (a ^ b))) + messageScheduleBuffer[j + 2] + 0x5a827999;
                    e = (e << 30) | (e >> 2);
                    b += ((c << 5) | (c >> 27)) + (a ^ (d & (e ^ a))) + messageScheduleBuffer[j + 3] + 0x5a827999;
                    d = (d << 30) | (d >> 2);
                    a += ((b << 5) | (b >> 27)) + (e ^ (c & (d ^ e))) + messageScheduleBuffer[j + 4] + 0x5a827999;
                    c = (c << 30) | (c >> 2);
                }

                /* Round 2 */
                for (; j < 40; j += 5)
                {
                    e += ((a << 5) | (a >> 27)) + (b ^ c ^ d) + messageScheduleBuffer[j] + 0x6ed9eba1;
                    b = (b << 30) | (b >> 2);
                    d += ((e << 5) | (e >> 27)) + (a ^ b ^ c) + messageScheduleBuffer[j + 1] + 0x6ed9eba1;
                    a = (a << 30) | (a >> 2);
                    c += ((d << 5) | (d >> 27)) + (e ^ a ^ b) + messageScheduleBuffer[j + 2] + 0x6ed9eba1;
                    e = (e << 30) | (e >> 2);
                    b += ((c << 5) | (c >> 27)) + (d ^ e ^ a) + messageScheduleBuffer[j + 3] + 0x6ed9eba1;
                    d = (d << 30) | (d >> 2);
                    a += ((b << 5) | (b >> 27)) + (c ^ d ^ e) + messageScheduleBuffer[j + 4] + 0x6ed9eba1;
                    c = (c << 30) | (c >> 2);
                }

                /* Round 3 */
                for (; j < 60; j += 5)
                {
                    e += ((a << 5) | (a >> 27)) + ((b & c) | (d & (b | c))) + messageScheduleBuffer[j] + 0x8f1bbcdc;
                    b = (b << 30) | (b >> 2);
                    d += ((e << 5) | (e >> 27)) + ((a & b) | (c & (a | b))) + messageScheduleBuffer[j + 1] + 0x8f1bbcdc;
                    a = (a << 30) | (a >> 2);
                    c += ((d << 5) | (d >> 27)) + ((e & a) | (b & (e | a))) + messageScheduleBuffer[j + 2] + 0x8f1bbcdc;
                    e = (e << 30) | (e >> 2);
                    b += ((c << 5) | (c >> 27)) + ((d & e) | (a & (d | e))) + messageScheduleBuffer[j + 3] + 0x8f1bbcdc;
                    d = (d << 30) | (d >> 2);
                    a += ((b << 5) | (b >> 27)) + ((c & d) | (e & (c | d))) + messageScheduleBuffer[j + 4] + 0x8f1bbcdc;
                    c = (c << 30) | (c >> 2);
                }

                /* Round 4 */
                for (; j < 80; j += 5)
                {
                    e += ((a << 5) | (a >> 27)) + (b ^ c ^ d) + messageScheduleBuffer[j] + 0xca62c1d6;
                    b = (b << 30) | (b >> 2);
                    d += ((e << 5) | (e >> 27)) + (a ^ b ^ c) + messageScheduleBuffer[j + 1] + 0xca62c1d6;
                    a = (a << 30) | (a >> 2);
                    c += ((d << 5) | (d >> 27)) + (e ^ a ^ b) + messageScheduleBuffer[j + 2] + 0xca62c1d6;
                    e = (e << 30) | (e >> 2);
                    b += ((c << 5) | (c >> 27)) + (d ^ e ^ a) + messageScheduleBuffer[j + 3] + 0xca62c1d6;
                    d = (d << 30) | (d >> 2);
                    a += ((b << 5) | (b >> 27)) + (c ^ d ^ e) + messageScheduleBuffer[j + 4] + 0xca62c1d6;
                    c = (c << 30) | (c >> 2);
                }

                #endregion Main compression loop

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

            UnsafeReference<uint> pMessageScheduleBuffer = new(messageScheduleBuffer, MESSAGE_SCHEDULE_BUFFER_LENGTH);

            // finalize the hash, zero used memory and fix endianness
            return HashFinalize(ref state, ref resultBuffer, ref pMessageScheduleBuffer);
        }
    }
}