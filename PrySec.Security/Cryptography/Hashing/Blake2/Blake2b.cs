using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Hashing.Blake2;

public unsafe partial class Blake2b : IHashFunctionScp
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

    static Blake2b()
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

    public TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input, Size32_T digestLength)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        ulong* hash = stackalloc ulong[8];
        Blake2State<TInputMemory> state = new(input, hash, 0u, digestLength);
        Initialize(ref state);
        TOutputMemory result = HashCore<TInputMemory, TOutputMemory>(ref state);
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
        return result;
    }

    private void Initialize<TInputMemory>(ref Blake2State<TInputMemory> state) where TInputMemory : IUnmanaged
    {
        // Initialize State vector h with IV
        fixed (ulong* pInitialHash = IV)
        {
            Unsafe.CopyBlockUnaligned(state.Hash, pInitialHash, IV_BYTE_SIZE);
        }

        // Mix key size (cbKeyLen) and desired hash length (cbHashLen) into h0
        *state.Hash ^= 0x01010000u | (state.KeyLength << 8) | state.DigestLength;
    }

    private TOutputMemory HashCore<TInputMemory, TOutputMemory>(ref Blake2State<TInputMemory> state)
        where TInputMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        TOutputMemory result;
        fixed (ulong* pIv = IV)
        {
            using (IMemoryAccess<byte> access = state.Input.GetAccess<byte>())
            {
                BlakeCompressionState compressionState = new(state.Hash, access.Pointer, pIv, access.ByteSize);
                HashCoreImpl(&compressionState);
            }
            result = TOutputMemory.Allocate(state.DigestLength);
            using IMemoryAccess<byte> resultAccess = result.GetAccess();
            Unsafe.CopyBlockUnaligned(resultAccess.Pointer, state.Hash, resultAccess.ByteSize);
        }

        // return first cbHashLen bytes of little endian state vector h
        return result;
    }
}