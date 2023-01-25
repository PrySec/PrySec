using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.MemoryProtection.Portable.Sentinels;

/// <summary>
/// Protects an already existing block of memory by guaranteeing that it is zeroed out before it is freed.
/// </summary>
/// <typeparam name="T"></typeparam>
public unsafe readonly struct DeterministicSentinel<T> : IProtectedMemory<T> where T : unmanaged
{
    public T* DataPointer => (T*)BasePointer;

    public void* BasePointer { get; }

    public int Count => 1;

    public Size_T ByteSize { get; }

    public IntPtr NativeHandle { get; }

    public Size_T NativeByteSize => ByteSize;

    public DeterministicSentinel(T* basePointer)
    {
        BasePointer = basePointer;
        ByteSize = sizeof(T);
        NativeHandle = new IntPtr(basePointer);
    }

    public void Dispose()
    {
        if (DataPointer != null)
        {
            ZeroMemory();
        }
    }

    public void Free() => Dispose();

    public void ZeroMemory() => MemoryManager.ZeroMemory(DataPointer, Count);

    public readonly MemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged =>
        new((TAs*)DataPointer, ByteSize / sizeof(TAs));

    readonly IMemoryAccess<TAs> IUnmanaged.GetAccess<TAs>() => GetAccess<TAs>();

    public readonly MemoryAccess<T> GetAccess() => new(DataPointer, Count);

    readonly IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();
}
