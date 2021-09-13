using PrySec.Base.Memory;
using PrySec.Base.Primitives;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Sha
{
    public abstract unsafe class Sha2UInt64Scp : ShaScpBase<ulong>
    {
        private const int WORD_SIZE_LOG_2 = 3;

        private protected const int DIGEST_DWORDLONG_LENGTH = 8;

        /// <summary>
        /// The length in bytes of the final Sha 256 digest
        /// </summary>
        private protected const int DIGEST_LENGTH = DIGEST_DWORDLONG_LENGTH * sizeof(ulong);

        /// <summary>
        /// The length of the message schedule array in 64-bit words.
        /// </summary>
        private protected const int MESSAGE_SCHEDULE_BUFFER_LENGTH = 80;

        private protected const int BLOCK_SIZE = 16 * sizeof(ulong);

        private protected readonly ulong[] H;

        private static readonly ulong[] K = new ulong[] {
              0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL, 0x3956c25bf348b538UL,
              0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL, 0xd807aa98a3030242UL, 0x12835b0145706fbeUL,
              0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL, 0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL,
              0xc19bf174cf692694UL, 0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
              0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL, 0x983e5152ee66dfabUL,
              0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL, 0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL,
              0x06ca6351e003826fUL, 0x142929670a0e6e70UL, 0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL,
              0x53380d139d95b3dfUL, 0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
              0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL, 0xd192e819d6ef5218UL,
              0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL, 0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL,
              0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL, 0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL,
              0x682e6ff3d6b2b8a3UL, 0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
              0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL, 0xca273eceea26619cUL,
              0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL, 0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL,
              0x113f9804bef90daeUL, 0x1b710b35131c471bUL, 0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL,
              0x431d67c49c100d4cUL, 0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL };

        private protected Sha2UInt64Scp(ulong[] initial) : base(WORD_SIZE_LOG_2)
        {
            H = initial;
        }

        private protected override void Initialize<T>(IUnmanaged<T> input, ref ShaScpState<ulong> state)
        {
            if (input.ByteSize > 0)
            {
                using IMemoryAccess<T> memoryAccess = input.GetAccess();
                Unsafe.CopyBlockUnaligned(state.Buffer.BasePointer, memoryAccess.Pointer, memoryAccess.ByteSize);
            }

            // append padding
            ((byte*)state.Buffer.BasePointer)[state.DataLength] = 0x80;

            // calculate length of original message in bits
            // write message length as 128 bit big endian unsigned integer to the end of the buffer
            *(UInt128BE*)(state.Buffer.BasePointer + state.Buffer.Size - 2) = new UInt128BE((ulong)state.DataLength << 3);

            // convert 64 bit word wise back to little endian.
            for (int i = 0; i < state.AllocatedSize; i++)
            {
                state.Buffer.BasePointer[i] = (UInt64BE)state.Buffer.BasePointer[i];
            }
        }

        private protected override DeterministicSpan<byte> HashFinalize(ref ShaScpState<ulong> state, ref DeterministicSpan<ulong> resultBuffer, ref UnsafeReference<ulong> messageScheduleBuffer)
        {
            // Zero used stack memory
            new Span<ulong>(messageScheduleBuffer.Pointer, messageScheduleBuffer.Size).Fill(0x0UL);

            // Fix endianness
            for (int i = 0; i < resultBuffer.Size; i++)
            {
                resultBuffer.BasePointer[i] = (UInt64BE)resultBuffer.BasePointer[i];
            }
            return resultBuffer.CastAs<byte>();
        }

        private protected DeterministicSpan<ulong> HashCoreHelper(ref ShaScpState<ulong> state, ulong* messageScheduleBuffer)
        {
            // create a buffer to hold the result
            DeterministicSpan<ulong> resultBuffer = new(DIGEST_DWORDLONG_LENGTH);

            // initialize result hash
            fixed (ulong* pInitialHash = H)
            {
                Unsafe.CopyBlockUnaligned(resultBuffer.BasePointer, pInitialHash, DIGEST_LENGTH);
            }

            ulong a, b, c, d, e, f, g, h;
            int j;

            // Process the message in successive 1024 - bit chunks (128 byte blocks / 16 ulong blocks)
            for (int i = 0; i < state.BlockCount; i++)
            {
                // copy current chunk (64 bytes) into first 16 words w[0..15] of the message schedule array
                Unsafe.CopyBlockUnaligned(messageScheduleBuffer, state.Buffer.BasePointer + (i << 4), BLOCK_SIZE);

                // Extend the first 16 words into the remaining 64 words w[16..80] of the message schedule array:
                for (j = 16; j < MESSAGE_SCHEDULE_BUFFER_LENGTH; j++)
                {
                    ulong s0In = messageScheduleBuffer[j - 15];
                    ulong s1In = messageScheduleBuffer[j - 2];

                    // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
                    ulong s0 = (s0In >> 1 | s0In << 63) ^ (s0In >> 8 | s0In << 56) ^ s0In >> 7;

                    // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
                    ulong s1 = (s1In >> 19 | s1In << 45) ^ (s1In >> 61 | s1In << 3) ^ s1In >> 6;

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
                    // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41))
                    ulong s1 = (e >> 14 | e << 50) ^ (e >> 18 | e << 46) ^ (e >> 41 | e << 23);

                    // ch:= (e and f) xor((not e) and g)
                    ulong ch = e & f ^ ~e & g;

                    // temp1:= h + S1 + ch + k[i] + w[i]
                    ulong temp1 = unchecked(h + s1 + ch + K[j] + messageScheduleBuffer[j]);

                    // S0:= (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
                    ulong s0 = (a >> 28 | a << 36) ^ (a >> 34 | a << 30) ^ (a >> 39 | a << 25);

                    // maj:= (a and b) xor(a and c) xor(b and c)
                    ulong maj = a & b ^ a & c ^ b & c;

                    // temp2:= S0 + maj
                    ulong temp2 = s0 + maj;

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