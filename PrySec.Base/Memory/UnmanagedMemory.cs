using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Core.Memory;

public unsafe class UnmanagedMemory<T> : IUnmanaged<T> where T : unmanaged
{
    public int Count { get; }

    public Size_T ByteSize { get; }

    public T* BasePointer { get; protected set; }

    public UnmanagedMemory(int size)
    {
        ByteSize = size * sizeof(T);
        Count = size;
        BasePointer = MemoryManager.Allocator.Calloc<T>(size);
    }

    public UnmanagedMemory(T[] arr)
    {
        Count = arr.Length;
        ByteSize = Count * sizeof(T);
        BasePointer = MemoryManager.Allocator.Calloc<T>(Count);
        if (arr.Length > 0)
        {
            fixed (T* pArr = arr)
            {
                Unsafe.CopyBlockUnaligned(BasePointer, pArr, (uint)arr.Length);
            }
        }
    }

    public virtual void Dispose()
    {
        if (BasePointer != null)
        {
            MemoryManager.Free(BasePointer);
            BasePointer = null;
            GC.SuppressFinalize(this);
        }
    }

    public void Free() => Dispose();

    public virtual MemoryAccess<T> GetAccess() => new(BasePointer, Count);

    IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();

    public virtual Span<T> AsSpan() => new(BasePointer, Count);

    public virtual MemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => new((TAs*)BasePointer, ByteSize / sizeof(TAs));

    IMemoryAccess<TAs> IUnmanaged<T>.GetAccess<TAs>() => GetAccess<TAs>();
}