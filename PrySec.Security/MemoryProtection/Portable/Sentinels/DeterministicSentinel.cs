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
    public T* BasePointer { get; }

    public int Count => 1;

    public Size_T ByteSize { get; }

    public IntPtr NativeHandle { get; }

    public Size_T NativeByteSize => ByteSize;

    public DeterministicSentinel(T* basePointer, Size_T byteSize)
    {
        BasePointer = basePointer;
        ByteSize = byteSize;
        NativeHandle = new IntPtr(basePointer);
    }

    public void Dispose()
    {
        if (BasePointer != null)
        {
            ZeroMemory();
        }
    }

    public void Free() => Dispose();

    public void ZeroMemory() => MemoryManager.ZeroMemory(BasePointer, Count);

    public readonly MemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged =>
        new((TAs*)BasePointer, ByteSize / sizeof(TAs));

    readonly IMemoryAccess<TAs> IUnmanaged.GetAccess<TAs>() => GetAccess<TAs>();

    public readonly MemoryAccess<T> GetAccess() => new(BasePointer, Count);

    readonly IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();
}
