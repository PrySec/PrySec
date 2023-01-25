using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Core.Memory;

public unsafe readonly struct UnmanagedMemory<T> : IUnmanaged<UnmanagedMemory<T>, T> where T : unmanaged
{
    public readonly int Count { get; }

    public readonly Size_T ByteSize { get; }

    public readonly void* BasePointer { get; }

    public readonly T* DataPointer => (T*)BasePointer;

    public UnmanagedMemory<T> this[Range range]
    {
        get
        {
            int size = range.End.Value - range.Start.Value;
            if (size <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(range));
            }
            UnmanagedMemory<T> deterministicSpan = new(size);
            MemoryManager.Memcpy(deterministicSpan.DataPointer, DataPointer + range.Start.Value, size);
            return deterministicSpan;
        }
    }

    public UnmanagedMemory(int count)
    {
        ByteSize = count * sizeof(T);
        BasePointer = MemoryManager.Calloc(count, sizeof(T));
        Count = count;
    }

    public void Dispose()
    {
        if (BasePointer != null)
        {
            MemoryManager.Free(BasePointer);
            GC.SuppressFinalize(this);
        }
    }

    public void Free() => Dispose();

    public readonly MemoryAccess<T> GetAccess() => new(DataPointer, Count);

    public readonly MemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => new((TAs*)DataPointer, ByteSize / sizeof(TAs));

    readonly IMemoryAccess<TAs> IUnmanaged.GetAccess<TAs>() => GetAccess<TAs>();

    readonly IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();

    public static UnmanagedMemory<T> Allocate(Size_T count) => new(count);

    public static UnmanagedMemory<T> CreateFrom(ReadOnlySpan<T> data)
    {
        UnmanagedMemory<T> span = UnmanagedMemory<T>.Allocate(data.Length);
        Span<T> destination = new(span.DataPointer, span.Count);
        data.CopyTo(destination);
        return span;
    }
}
