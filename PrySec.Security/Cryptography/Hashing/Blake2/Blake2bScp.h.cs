using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Portable;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Hashing.Blake2;

public unsafe partial class Blake2bScp
{
    private static readonly ulong[] IV = new ulong[]
    {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };

    private const uint IV_BYTE_SIZE = 64;
    private const uint DIGEST_BYTE_SIZE = 64;

    private static readonly int* SIGMA;

    private static readonly delegate*<BlakeCompressionState*, void> HashCoreImpl;

    static Blake2bScp()
    {
        SIGMA = (int*)MemoryManager.Malloc(16 * sizeof(int) * 12);
        int* pSigma = SIGMA;
        for (int i = 0; i < 12; i++, pSigma += 16)
        {
            for (int j = 0; j < 16; j++)
            {
                pSigma[j] = SIGMA_IV[i, j];
            }
        }
        HashCoreImpl = true switch
        {
            _ when Avx2.IsSupported => &Blake2HwIntrinsicsAvx2.HashCore,
            _ => &Blake2HwIntrinsicsDefault.HashCore
        };
    }

    private readonly struct Blake2State<TInputMemory>
        where TInputMemory : IUnmanaged
    {
        public readonly TInputMemory Input;
        public readonly ulong* Hash;
        public readonly uint KeyLength;
        public readonly uint DigestLength;

        public Blake2State(TInputMemory input, ulong* hash, uint keyLength, uint digestLength)
        {
            Input = input;
            Hash = hash;
            KeyLength = keyLength;
            DigestLength = digestLength;
        }
    }

    private struct BlakeCompressionState
    {
        public readonly ulong* Hash;
        public byte* WorkVector;
        public readonly ulong* Iv;
        public byte* Input;
        public fixed ulong BytesCompressed[2];
        public ulong BytesRemaining;
        public ulong StateMask;

        public BlakeCompressionState(ulong* hash, byte* input, ulong* iv, nuint bytesRemaining)
        {
            WorkVector = null;
            Hash = hash;
            Input = input;
            Iv = iv;
            BytesRemaining = bytesRemaining;
            BytesCompressed[0] = 0;
            BytesCompressed[1] = 0;
            StateMask = (ulong)CompressionStateMask.NotLastBlock;
        }

        public static void IncrementCompressedBytes(BlakeCompressionState* state, ulong value)
        {
            state->BytesCompressed[0] += value;
            if (state->BytesCompressed[0] > value)
            {
                state->BytesCompressed[0]++;
            }
        }
    }

    private enum CompressionStateMask : ulong
    {
        NotLastBlock = 0x0UL,
        LastBlock = ~NotLastBlock,
    }

    private static readonly int[,] SIGMA_IV = new int[12, 16]
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };
}