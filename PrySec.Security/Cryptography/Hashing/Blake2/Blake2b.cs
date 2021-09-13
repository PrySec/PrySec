using PrySec.Base;
using PrySec.Base.Memory;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Blake2
{
    public unsafe class Blake2b : IHashFunctionScp
    {
        private static readonly ulong[] H = new ulong[] {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
            0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
            0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
            0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL };

        public IUnmanaged<byte> ComputeHash<T>(ref IUnmanaged<T> input) where T : unmanaged => 
            ComputeHash(ref input, 32);

        public IUnmanaged<byte> ComputeHash<T>(ref IUnmanaged<T> input, Size_T digestLength) where T : unmanaged
        {
            ulong* hash = stackalloc ulong[8];
            Blake2State<T> state = new(input, hash, 0u, digestLength);
            return Initialize(ref state);
        }

        public IUnmanaged<byte> ComputeHash<T, T2>(ref IUnmanaged<T> input, ref IUnmanaged<T2> key, Size_T digestLength) where T : unmanaged where T2 : unmanaged
        {
            uint keyLength = key.ByteSize;
            if (keyLength > 64)
            {
                throw new ArgumentOutOfRangeException(nameof(key), "Length cannot be > 64!");
            }
            using DeterministicSpan<byte> paddedInput = new(input.ByteSize + 128);
            new Span<ulong>(paddedInput.BasePointer, 16).Fill(0x0UL);
            using (IMemoryAccess<T2> access = key.GetAccess())
            {
                Unsafe.CopyBlockUnaligned(paddedInput.BasePointer, access.Pointer, access.ByteSize);
            }
            using (IMemoryAccess<T> access = input.GetAccess())
            {
                Unsafe.CopyBlockUnaligned(paddedInput.BasePointer + keyLength, access.Pointer, access.ByteSize);
            }
            ulong* hash = stackalloc ulong[8];

            Blake2State<byte> state = new(paddedInput, hash, keyLength, digestLength);
            return Initialize(ref state);
        }

        private void Initialize<T>(ref Blake2State<T> state) where T : unmanaged
        {
            fixed (ulong* pInitialHash = H)
            {
                Unsafe.CopyBlockUnaligned(state.Hash, pInitialHash, 64);
            }
            *state.Hash ^= 0x01010000u | (state.KeyLength << 8) | state.DigestLength;

            uint bytesCompressed = 0;
            uint bytesRemaining = state.Input.ByteSize;
        }

        private DeterministicSpan<byte> HashCore<T>(ref Blake2State<T> state) where T : unmanaged
        {
            uint bytesCompressed = 0u;
            uint bytesRemaining = state.Input.ByteSize;
            uint chunkOffset = 0u;

            while (bytesRemaining > 128)
            {
                bytesCompressed += 128;
                bytesRemaining -= 128;
                Compress(ref state, chunkOffset, bytesCompressed, )
                chunkOffset = bytesCompressed;
            }
        }

        private static void Compress(ref Blake2State<T> state, uint chunkOffset, uint bytesCompressed, )

        private readonly ref struct Blake2State<T> where T : unmanaged
        {
            public readonly IUnmanaged<T> Input;
            public readonly ulong* Hash;
            public readonly uint KeyLength;
            public readonly uint DigestLength;
            public Blake2State(IUnmanaged<T> input, ulong* hash, uint keyLength, uint digestLength)
            {
                Input = input;
                Hash = hash;
                KeyLength = keyLength;
                DigestLength = digestLength;
            }
        }
    }
}