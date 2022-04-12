using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Blake2;

public unsafe partial class Blake2b
{
    private static class Blake2HwIntrinsicsDefault
    {
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

        private static void Compress(BlakeCompressionState* state)
        {
            // Setup local work vector V
            // First eight items are copied from persistent state vector h
            ulong* v = state->Hash;
            ulong v0 = v[0];
            ulong v1 = v[1];
            ulong v2 = v[2];
            ulong v3 = v[3];
            ulong v4 = v[4];
            ulong v5 = v[5];
            ulong v6 = v[6];
            ulong v7 = v[7];

            // Remaining eight items are initialized from the IV
            v = state->Iv;
            ulong v8 = v[0];
            ulong v9 = v[1];
            ulong v10 = v[2];
            ulong v11 = v[3];

            // Mix the 128 - bit counter t into ref v12:ref v13
            ulong v12 = v[4] ^ state->BytesCompressed[0];
            ulong v13 = v[5] ^ state->BytesCompressed[1];

            // If this is the last block then invert all the bits in ref v14
            ulong v14 = v[6] ^ state->StateMask;
            ulong v15 = v[7];

            // Treat each 128-byte message chunk as sixteen 8-byte (64-bit) words m
            ulong* message = (ulong*)state->Input;
            int* sigma = SIGMA;

            // Twelve rounds of cryptographic message mixing
            for (int i = 0; i < 12; i++, sigma += 16)
            {
                Mix(ref v0, ref v4, ref v8, ref v12, message[sigma[0]], message[sigma[1]]);
                Mix(ref v1, ref v5, ref v9, ref v13, message[sigma[2]], message[sigma[3]]);
                Mix(ref v2, ref v6, ref v10, ref v14, message[sigma[4]], message[sigma[5]]);
                Mix(ref v3, ref v7, ref v11, ref v15, message[sigma[6]], message[sigma[7]]);

                Mix(ref v0, ref v5, ref v10, ref v15, message[sigma[8]], message[sigma[9]]);
                Mix(ref v1, ref v6, ref v11, ref v12, message[sigma[10]], message[sigma[11]]);
                Mix(ref v2, ref v7, ref v8, ref v13, message[sigma[12]], message[sigma[13]]);
                Mix(ref v3, ref v4, ref v9, ref v14, message[sigma[14]], message[sigma[15]]);
            }
            // Mix the upper and lower halves of V into ongoing state vector h
            state->Hash[0] ^= v0 ^ v8;
            state->Hash[1] ^= v1 ^ v9;
            state->Hash[2] ^= v2 ^ v10;
            state->Hash[3] ^= v3 ^ v11;
            state->Hash[4] ^= v4 ^ v12;
            state->Hash[5] ^= v5 ^ v13;
            state->Hash[6] ^= v6 ^ v14;
            state->Hash[7] ^= v7 ^ v15;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mix(ref ulong va, ref ulong vb, ref ulong vc, ref ulong vd, in ulong x, in ulong y)
        {
            // with input
            va = va + vb + x;
            vd = RotateRight(vd ^ va, 32);

            // no input
            vc += vd;
            vb = RotateRight(vb ^ vc, 24);

            // with input
            va = va + vb + y;
            vd = RotateRight(vd ^ va, 16);

            // no input
            vc += vd;
            vb = RotateRight(vb ^ vc, 63);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong RotateRight(ulong x, byte n) =>
            (x >> n) | (x << (64 - n));
    }
}
