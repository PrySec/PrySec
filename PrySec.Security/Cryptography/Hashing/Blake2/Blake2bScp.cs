using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Portable;
using PrySec.Security.MemoryProtection.Portable.Sentinels;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Blake2;

public unsafe partial class Blake2bScp : IVariableLengthKeyedHashFunctionScp
{
    #region interface implementation

    private const int DEFAULT_DIGEST_BYTE_SIZE = 64;

    #region IVariableLengthHashFunctionScp

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> ComputeHash(IUnmanaged input, Size_T outputLength) => 
        ComputeHash<IUnmanaged, DeterministicMemory<byte>>(ref input, outputLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> ComputeHash<TInputMemory>(ref TInputMemory input, Size_T outputLength) 
        where TInputMemory : IUnmanaged =>
        ComputeHash<TInputMemory, DeterministicMemory<byte>>(ref input, outputLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHash<TOutputMemory>(IUnmanaged input, Size_T outputLength) 
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHash<IUnmanaged, TOutputMemory>(ref input, outputLength);

    #endregion IVariableLengthHashFunctionScp

    #region IHashFunctionScp

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> ComputeHash(IUnmanaged input) =>
        ComputeHash<IUnmanaged, DeterministicMemory<byte>>(ref input, DEFAULT_DIGEST_BYTE_SIZE);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> ComputeHash<TInputMemory>(ref TInputMemory input) 
        where TInputMemory : IUnmanaged =>
        ComputeHash<TInputMemory, DeterministicMemory<byte>>(ref input, DEFAULT_DIGEST_BYTE_SIZE);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHash<TOutputMemory>(IUnmanaged input) 
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHash<IUnmanaged, TOutputMemory>(ref input, DEFAULT_DIGEST_BYTE_SIZE);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHash<TInputMemory, TOutputMemory>(ref TInputMemory input)
        where TInputMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHash<TInputMemory, TOutputMemory>(ref input, DEFAULT_DIGEST_BYTE_SIZE);

    #endregion IHashFunctionScp

    #region IVariableLengthKeyedHashFunctionScp

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> ComputeHashKeyed(IUnmanaged input, IUnmanaged key, Size_T outputLength) =>
        ComputeHashKeyed<IUnmanaged, IUnmanaged, DeterministicMemory<byte>>(ref input, ref key, outputLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> ComputeHashKeyed<TMemory>(ref TMemory input, ref TMemory key, Size_T outputLength) 
        where TMemory : IUnmanaged =>
        ComputeHashKeyed<TMemory, TMemory, DeterministicMemory<byte>>(ref input, ref key, outputLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHashKeyed<TOutputMemory>(IUnmanaged input, IUnmanaged key, Size_T outputLength) 
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHashKeyed<IUnmanaged, IUnmanaged, TOutputMemory>(ref input, ref key, outputLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHashKeyed<TMemory, TOutputMemory>(ref TMemory input, ref TMemory key, Size_T outputLength)
        where TMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHashKeyed<TMemory, TMemory, TOutputMemory>(ref input, ref key, outputLength);

    #endregion IVariableLengthKeyedHashFunctionScp

    #region IKeyedHashFunctionScp

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> ComputeHashKeyed(IUnmanaged input, IUnmanaged key) =>
        ComputeHashKeyed<IUnmanaged, IUnmanaged, DeterministicMemory<byte>>(ref input, ref key, DEFAULT_DIGEST_BYTE_SIZE);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> ComputeHashKeyed<TMemory>(ref TMemory input, ref TMemory key) 
        where TMemory : IUnmanaged =>
        ComputeHashKeyed<TMemory, TMemory, DeterministicMemory<byte>>(ref input, ref key, DEFAULT_DIGEST_BYTE_SIZE);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHashKeyed<TOutputMemory>(IUnmanaged input, IUnmanaged key) 
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHashKeyed<IUnmanaged, IUnmanaged, TOutputMemory>(ref input, ref key, DEFAULT_DIGEST_BYTE_SIZE);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHashKeyed<TMemory, TOutputMemory>(ref TMemory input, ref TMemory key)
        where TMemory : IUnmanaged 
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHashKeyed<TMemory, TMemory, TOutputMemory>(ref input, ref key, DEFAULT_DIGEST_BYTE_SIZE);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHashKeyed<TInputMemory, TKeyMemory, TOutputMemory>(ref TInputMemory input, ref TKeyMemory key)
        where TInputMemory : IUnmanaged
        where TKeyMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHashKeyed<TInputMemory, TKeyMemory, TOutputMemory>(ref input, ref key, DEFAULT_DIGEST_BYTE_SIZE);

    #endregion IKeyedHashFunctionScp

    #endregion interface implementation

    #region core driver

    public TOutputMemory ComputeHash<TInputMemory, TOutputMemory>(ref TInputMemory input, Size_T outputLength)
        where TInputMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        ulong* hash = stackalloc ulong[8];
        using DeterministicMemory<ulong> hashSentinel = DeterministicMemory.ProtectOnly(hash, 8 * sizeof(ulong));
        Blake2State<TInputMemory> state = new(input, hash, 0u, outputLength);
        Initialize(ref state);
        TOutputMemory result = HashCore<TInputMemory, TOutputMemory>(ref state);
        return result;
    }

    public TOutputMemory ComputeHashKeyed<TInputMemory, TKeyMemory, TOutputMemory>(ref TInputMemory input, ref TKeyMemory key, Size_T outputLength)
        where TInputMemory : IUnmanaged
        where TKeyMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        uint keyLength = key.ByteSize;
        if (keyLength > 64)
        {
            throw new ArgumentOutOfRangeException(nameof(key), "Length cannot be > 64!");
        }
        // If there was a key supplied (i.e. cbKeyLen > 0)
        // then pad with trailing zeros to make it 128 - bytes(i.e. 16 words)
        // and prepend it to the message M
        using DeterministicMemory<byte> paddedInput = new(input.ByteSize + 128);
        using (IMemoryAccess<byte> access = key.GetAccess<byte>())
        {
            MemoryManager.Memcpy(paddedInput.DataPointer, access.Pointer, access.ByteSize);
        }
        using (IMemoryAccess<byte> access = input.GetAccess<byte>())
        {
            MemoryManager.Memcpy(paddedInput.DataPointer + keyLength, access.Pointer, access.ByteSize);
        }
        ulong* hash = stackalloc ulong[8];
        using DeterministicMemory<ulong> hashSentinel = DeterministicMemory.ProtectOnly(hash, 8 * sizeof(ulong));

        Blake2State<DeterministicMemory<byte>> state = new(paddedInput, hash, keyLength, outputLength);
        Initialize(ref state);
        TOutputMemory result = HashCore<DeterministicMemory<byte>, TOutputMemory>(ref state);
        return result;
    }

    #endregion core driver
}