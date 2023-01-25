using PrySec.Core.HwPrimitives;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Hashing.Blake2;

public unsafe partial class Blake2bScp
{
    private static class Blake2HwIntrinsicsAvx2
    {
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static void HashCore(BlakeCompressionState* state)
        {
            Size_T CHUNK_BYTE_SIZE = 128;

            while (state->BytesRemaining > CHUNK_BYTE_SIZE)
            {
                BlakeCompressionState.IncrementCompressedBytes(state, CHUNK_BYTE_SIZE);
                state->BytesRemaining -= CHUNK_BYTE_SIZE;
                Compress(state);
                state->Input += CHUNK_BYTE_SIZE;
            }
            BlakeCompressionState.IncrementCompressedBytes(state, state->BytesRemaining);

            // If M was empty, then we will still compress a final chunk of zeros
            byte* paddedInput = stackalloc byte[CHUNK_BYTE_SIZE];
            MemoryManager.ZeroMemory(paddedInput, CHUNK_BYTE_SIZE);
            if (state->BytesRemaining > 0)
            {
                Unsafe.CopyBlockUnaligned(paddedInput, state->Input, (uint)state->BytesRemaining);
            }
            state->Input = paddedInput;
            state->StateMask = (ulong)CompressionStateMask.LastBlock;
            Compress(state);
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization | MethodImplOptions.AggressiveInlining)]
        private static void Compress(BlakeCompressionState* state)
        {
            Vector256<ulong> xorMask = Vector256.Create
            (
                // Mix the 128 - bit counter t into what is going to become V12:V13
                state->BytesCompressed[0],
                state->BytesCompressed[1],

                // If this is the last block then invert all the bits in V14
                state->StateMask,

                // the last word remains unchanged
                0UL
            );

            ulong* message = (ulong*)state->Input;

            int* sigma = SIGMA;
            Vector256<ulong> va = Avx.LoadDquVector256(state->Hash);
            Vector256<ulong> vb = Avx.LoadDquVector256(state->Hash + 4);
            Vector256<ulong> vc = Avx.LoadDquVector256(state->Iv);
            Vector256<ulong> vd = Avx.LoadDquVector256(state->Iv + 4);

            // mix state information into vd
            vd = Avx2.Xor(vd, xorMask);

            for (int i = 0; i < 12; i++, sigma += 16)
            {
                //     va  vb  vc  vd   x       y
                // Mix(V0, V4, V8,  V12, m[S0], m[S1])
                // Mix(V1, V5, V9, V13, m[S2], m[S3])
                // Mix(V2, V6, V10, V14, m[S4], m[S5])
                // Mix(V3, V7, V11, V15, m[S6], m[S7])

                // load the first half of the input ...
                Vector256<ulong> x = Vector256.Create(message[sigma[0]], message[sigma[2]], message[sigma[4]], message[sigma[6]]);
                Vector256<ulong> y = Vector256.Create(message[sigma[1]], message[sigma[3]], message[sigma[5]], message[sigma[7]]);

                // do 4 mix steps in one go
                Mix(ref va, ref vb, ref vc, ref vd, in x, in y);

                //     va  vb  vc  vd   x       y
                // Mix(V0, V5, V10, V15, m[S8], m[S9])
                // Mix(V1, V6, V11, V12, m[S10], m[S11])
                // Mix(V2, V7, V8, V13, m[S12], m[S13])
                // Mix(V3, V4, V9, V14, m[S14], m[S15])

                // va stays as it is
                // vb is rotated left by 64 bit
                vb = AvxPrimitives.RotateLaneLeft64Bit(vb);

                // in vc upper and lower 128 bit lanes are swapped
                vc = Avx.Permute2x128(vc, vc, 1);

                // vd is rotated right by 64 bit
                vd = AvxPrimitives.RotateLaneRight64Bit(vd);

                // load the remaining input ...
                x = Vector256.Create(message[sigma[8]], message[sigma[10]], message[sigma[12]], message[sigma[14]]);
                y = Vector256.Create(message[sigma[9]], message[sigma[11]], message[sigma[13]], message[sigma[15]]);

                // do 4 mix steps in one go
                Mix(ref va, ref vb, ref vc, ref vd, in x, in y);

                // now reverse the vector element permutations and store the result in the ongoing work vectors
                // va stays as it is
                // vb is rotated right by 64 bit
                vb = AvxPrimitives.RotateLaneRight64Bit(vb);

                // in vc upper and lower 128 bit lanes are swapped
                vc = Avx.Permute2x128(vc, vc, 1);

                // vd is rotated left by 64 bit
                vd = AvxPrimitives.RotateLaneLeft64Bit(vd);
            }
            // Mix the upper and lower halves of V into ongoing state vector h
            Vector256<ulong> h0 = Avx.LoadDquVector256(state->Hash);
            Vector256<ulong> h1 = Avx.LoadDquVector256(state->Hash + 4);
            h0 = Avx2.Xor(Avx2.Xor(h0, va), vc);
            h1 = Avx2.Xor(Avx2.Xor(h1, vb), vd);

            Avx.Store(state->Hash, h0);
            Avx.Store(state->Hash + 4, h1);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mix(ref Vector256<ulong> va, ref Vector256<ulong> vb, ref Vector256<ulong> vc, ref Vector256<ulong> vd, in Vector256<ulong> x, in Vector256<ulong> y)
        {
            // with input
            va = Avx2.Add(Avx2.Add(va, vb), x);
            vd = RotateRight(Avx2.Xor(vd, va), 32);

            // no input
            vc = Avx2.Add(vc, vd);
            vb = RotateRight(Avx2.Xor(vb, vc), 24);

            // with input
            va = Avx2.Add(Avx2.Add(va, vb), y);
            vd = RotateRight(Avx2.Xor(vd, va), 16);

            // no input
            vc = Avx2.Add(vc, vd);
            vb = RotateRight(Avx2.Xor(vb, vc), 63);
        }

        // ROTR(x,n) (((x) >> (n)) | ((x) << ((sizeof(x) * 8) - (n))))
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> RotateRight(Vector256<ulong> vector, byte n) =>
            Avx2.Or(Avx2.ShiftRightLogical(vector, n), Avx2.ShiftLeftLogical(vector, (byte)((sizeof(ulong) << 3) - n)));
    }
}