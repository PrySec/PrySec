using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Portable;
using PrySec.Security.MemoryProtection.Portable.Sentinels;
using System;
using System.Runtime.CompilerServices;
using System.Text;

namespace PrySec.Security.Cryptography.Hashing.Blake3;

public unsafe partial class Blake3 : IHashFunctionScp
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<T>(ref IUnmanaged<T> input) where T : unmanaged =>
        ComputeHash<T, IUnmanaged<T>, DeterministicMemory<byte>>(ref input);

    public TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input, int outputLength)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
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
            Blake3Context.Finalize(&context, access.Pointer, access.ByteSize);
        }
        return output;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> => 
        ComputeHash<TData, TInputMemory, TOutputMemory>(ref input, BLAKE3_OUT_LEN);

    /// <summary>
    /// 
    /// </summary>
    /// <typeparam name="TData"></typeparam>
    /// <typeparam name="TInputMemory"></typeparam>
    /// <typeparam name="TOutputMemory"></typeparam>
    /// <param name="input"></param>
    /// <param name="context">
    /// The <paramref name="context"/> string is given as an initialization parameter together with input key material. 
    /// The <paramref name="context"/> string should be hardcoded, globally unique, and application-specific. 
    /// The <paramref name="context"/> string should not include any dynamic input like salts, nonces, or identifiers read from a database at runtime. 
    /// A good default format for the <paramref name="context"/> string is <c>"[application] [commit timestamp] [purpose]"</c>, e.g., <c>"example.com 2019-12-25 16:18:03 session tokens v1"</c></param>
    /// <returns></returns>
    public unsafe TOutputMemory DeriveKey<TData, TInputMemory, TOutputMemory>(ref TInputMemory input, string context, Size_T requestedBytes)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        Blake3Context blake3 = default;
        using DeterministicSentinel<Blake3Context> _ = DeterministicSentinel.Protect(&blake3);
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
        Blake3Context.InitializeDeriveKey(&blake3, contextBytesPtr, (ulong)contextByteCount);
        if (!isStackAllocation)
        {
            MemoryManager.Free(contextBytesPtr);
        }
        using (IMemoryAccess<byte> access = input.GetAccess<byte>())
        {
            Blake3Context.Update(&blake3, access.Pointer, access.ByteSize);
        }
        TOutputMemory output = TOutputMemory.Allocate(requestedBytes);
        using (IMemoryAccess<byte> access = output.GetAccess())
        {
            Blake3Context.Finalize(&blake3, access.Pointer, access.ByteSize);
        }
        return output;
    }
}
