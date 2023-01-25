using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.Cryptography.Hashing.Blake3.Implementation;
using PrySec.Security.MemoryProtection.Portable;
using PrySec.Security.MemoryProtection.Portable.Sentinels;
using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace PrySec.Security.Cryptography.Hashing.Blake3;

public unsafe partial class Blake3Scp : Blake3__EffectiveArch, IVariableLengthKeyedHashFunctionScp, IKeyDerivationFunctionScp
{
    public string KeyDerivationContext { get; } = "example.com 1970-01-01 00:00:00 unspecified use case";

    public Blake3Scp(string keyDerivationContext) => KeyDerivationContext = keyDerivationContext;

    public Blake3Scp()
    {
    }

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

    #region IKeyDerivationFunctionScp

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> DeriveKey(IUnmanaged key, Size_T derivedKeyLength) => 
        DeriveKey<IUnmanaged, DeterministicMemory<byte>>(ref key, derivedKeyLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public DeterministicMemory<byte> DeriveKey<TKeyMemory>(ref TKeyMemory key, Size_T derivedKeyLength) 
        where TKeyMemory : IUnmanaged =>
        DeriveKey<TKeyMemory, DeterministicMemory<byte>>(ref key, derivedKeyLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory DeriveKey<TOutputMemory>(IUnmanaged key, Size_T derivedKeyLength) 
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        DeriveKey<IUnmanaged, TOutputMemory>(ref key, derivedKeyLength);

    #endregion IKeyDerivationFunctionScp

    #endregion interface implementation

    #region core driver

    public TOutputMemory ComputeHash<TInputMemory, TOutputMemory>(ref TInputMemory input, Size_T outputLength)
        where TInputMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        Blake3Context context = default;
        using DeterministicSentinel<Blake3Context> _ = DeterministicSentinel.Protect(&context);
        Blake3Context.Initialize(&context);
        using (IMemoryAccess<byte> access = input.GetAccess<byte>())
        {
            Blake3Context.Update(&context, access.Pointer, access.ByteSize);
        }
        TOutputMemory output = TOutputMemory.Allocate(outputLength);
        using (IMemoryAccess<byte> access = output.GetAccess())
        {
            Blake3Context.Finalize(&context, access.Pointer, outputLength);
        }
        return output;
    }

    public TOutputMemory ComputeHashKeyed<TInputMemory, TKeyMemory, TOutputMemory>(ref TInputMemory input, ref TKeyMemory key, Size_T outputLength)
        where TInputMemory : IUnmanaged
        where TKeyMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        if (key.ByteSize != BLAKE3_KEY_LEN)
        {
            throw new ArgumentOutOfRangeException(nameof(key), "key must be 32 bytes in length");
        }
        Blake3Context context = default;
        using DeterministicSentinel<Blake3Context> _ = DeterministicSentinel.Protect(&context);
        using (IMemoryAccess<byte> access = key.GetAccess<byte>())
        {
            Blake3Context.InitializeKeyed(&context, access.Pointer);
        }
        using (IMemoryAccess<byte> access = input.GetAccess<byte>())
        {
            Blake3Context.Update(&context, access.Pointer, access.ByteSize);
        }
        TOutputMemory output = TOutputMemory.Allocate(outputLength);
        using (IMemoryAccess<byte> access = output.GetAccess())
        {
            Blake3Context.Finalize(&context, access.Pointer, access.ByteSize);
        }
        return output;
    }

    public TOutputMemory DeriveKey<TKeyMemory, TOutputMemory>(ref TKeyMemory input, Size_T derivedKeyLength)
        where TKeyMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        Blake3Context blake3 = default;
        using DeterministicSentinel<Blake3Context> _ = DeterministicSentinel.Protect(&blake3);
        InternalInitializeDeriveKeyFromContext(&blake3, KeyDerivationContext);
        using (IMemoryAccess<byte> access = input.GetAccess<byte>())
        {
            Blake3Context.Update(&blake3, access.Pointer, access.ByteSize);
        }
        TOutputMemory output = TOutputMemory.Allocate(derivedKeyLength);
        using (IMemoryAccess<byte> access = output.GetAccess())
        {
            Blake3Context.Finalize(&blake3, access.Pointer, access.ByteSize);
        }
        return output;
    }

    internal static void InternalInitializeDeriveKeyFromContext(Blake3Context* blake3, string context)
    {
        int contextByteCount = Encoding.UTF8.GetByteCount(context);
        byte* contextBytesPtr = null;
        bool isStackAllocation = true;
        if (contextByteCount < MemoryManager.MaxStackAllocSize)
        {
            byte* pStackContextBytes = stackalloc byte[contextByteCount];
            contextBytesPtr = pStackContextBytes;
        }
        else
        {
            contextBytesPtr = (byte*)MemoryManager.Malloc(contextByteCount);
            isStackAllocation = false;
        }
        Span<byte> contextBytes = new(contextBytesPtr, contextByteCount);
        Encoding.Default.GetBytes(context, contextBytes);
        Blake3Context.InitializeDeriveKey(blake3, contextBytesPtr, (ulong)contextByteCount);
        if (!isStackAllocation)
        {
            MemoryManager.Free(contextBytesPtr);
        }
    }

    #endregion core driver
}
