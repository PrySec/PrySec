using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Core.Memory;

public unsafe readonly struct UnmanagedMemory<T> : IUnmanaged<UnmanagedMemory<T>, T> where T : unmanaged
{
    public readonly IntPtr Handle { get; }

    public readonly int Count { get; }

    public readonly Size_T ByteSize { get; }

    public readonly T* BasePointer { get; }

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
            Unsafe.CopyBlockUnaligned(deterministicSpan.BasePointer, BasePointer + range.Start.Value, (uint)size);
            return deterministicSpan;
        }
    }

    public UnmanagedMemory(int count)
    {
        ByteSize = count * sizeof(T);
        BasePointer = (T*)MemoryManager.Calloc(count, sizeof(T));
        Handle = new IntPtr(BasePointer);
        Count = count;
    }

    public void Dispose()
    {
        if (Handle != IntPtr.Zero)
        {
            MemoryManager.Free(BasePointer);
            GC.SuppressFinalize(this);
        }
    }

    public void Free() => Dispose();

    public readonly MemoryAccess<T> GetAccess() => new(BasePointer, Count);

    public readonly MemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => new((TAs*)BasePointer, ByteSize / sizeof(TAs));

    readonly IMemoryAccess<TAs> IUnmanaged.GetAccess<TAs>() => GetAccess<TAs>();

    readonly IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();

    public static UnmanagedMemory<T> Allocate(Size_T count) => new(count);

    public static UnmanagedMemory<T> CreateFrom(ReadOnlySpan<T> data)
    {
        UnmanagedMemory<T> span = UnmanagedMemory<T>.Allocate(data.Length);
        Span<T> destination = new(span.BasePointer, span.Count);
        data.CopyTo(destination);
        return span;
    }
}
