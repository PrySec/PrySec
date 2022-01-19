using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Blake2;

public unsafe partial class Blake2b : IHashFunctionScp
{
    private static readonly ulong[] H = new ulong[] 
    {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL 
    };

    public TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input, Size32_T digestLength)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        ulong* hash = stackalloc ulong[8];
        Blake2State<TInputMemory> state = new(input, hash, 0u, digestLength);
        Initialize(ref state);
        TOutputMemory result = HashCore<TInputMemory, TOutputMemory>(ref state);
        // TODO: finalize?
        return result;
    }

    public IUnmanaged<byte> ComputeHash<TData, TKey, TDataInputMemory, TKeyInputMemory, TOutputMemory>(ref TDataInputMemory input, ref TKeyInputMemory key, Size32_T digestLength)
        where TDataInputMemory : IUnmanaged<TData>
        where TKeyInputMemory : IUnmanaged<TKey>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
        where TData : unmanaged
        where TKey : unmanaged
    {
        uint keyLength = key.ByteSize;
        if (keyLength > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(key), "Length cannot be > 64!");
        }
        // If there was a key supplied (i.e. cbKeyLen > 0)
        // then pad with trailing zeros to make it 128 - bytes(i.e. 16 words)
        // and prepend it to the message M
        using DeterministicSpan<byte> paddedInput = new(input.ByteSize + 128);
        using (IMemoryAccess<TKey> access = key.GetAccess())
        {
            Unsafe.CopyBlockUnaligned(paddedInput.BasePointer, access.Pointer, access.ByteSize);
        }
        using (IMemoryAccess<TData> access = input.GetAccess())
        {
            Unsafe.CopyBlockUnaligned(paddedInput.BasePointer + keyLength, access.Pointer, access.ByteSize);
        }
        ulong* hash = stackalloc ulong[8];

        Blake2State<DeterministicSpan<byte>> state = new(paddedInput, hash, keyLength, digestLength);
        Initialize(ref state);
        TOutputMemory result = HashCore<DeterministicSpan<byte>, TOutputMemory>(ref state);
        // TODO: finalize?
        return result;
    }

    private void Initialize<TInputMemory>(ref Blake2State<TInputMemory> state) where TInputMemory : IUnmanaged
    {
        // Initialize State vector h with IV
        fixed (ulong* pInitialHash = H)
        {
            Unsafe.CopyBlockUnaligned(state.Hash, pInitialHash, 64);
        }

        // Mix key size (cbKeyLen) and desired hash length (cbHashLen) into h0
        *state.Hash ^= 0x01010000u | (state.KeyLength << 8) | state.DigestLength;
    }

    private TOutputMemory HashCore<TInputMemory, TOutputMemory>(ref Blake2State<TInputMemory> state)
        where TInputMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        uint bytesCompressed = 0u;
        uint bytesRemaining = state.Input.ByteSize;
        uint chunkOffset = 0u;

        while (bytesRemaining > 128)
        {
            bytesCompressed += 128;
            bytesRemaining -= 128;
            Compress(ref state, chunkOffset, bytesCompressed);
            chunkOffset = bytesCompressed;
        }
        // TODO:
        return default;
    }

    private static void Compress<TInputMemory>(ref Blake2State<TInputMemory> state, uint chunkOffset, uint bytesCompressed)
        where TInputMemory : IUnmanaged
    {
    }

    public TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHash<TData, TInputMemory, TOutputMemory>(ref input, 32);

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
}