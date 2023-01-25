using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.MemoryProtection.Portable;

public unsafe readonly struct DeterministicMemory<T> : IProtectedMemoryFactory<DeterministicMemory<T>, T> where T : unmanaged
{
    public readonly int Count { get; }

    public readonly Size_T ByteSize { get; }

    public readonly T* DataPointer => (T*)BasePointer;

    public readonly void* BasePointer { get; }

    public readonly IntPtr NativeHandle { get; }

    /// <summary>
    /// Indicates whether this instance is allowed to free the underlying memory or whether it is managed externally.
    /// </summary>
    public readonly bool WillFreeAllocatedMemory { get; } = false;

    public Size_T NativeByteSize => ByteSize;

    public DeterministicMemory<T> this[Range range]
    {
        get
        {
            int count = range.End.Value - range.Start.Value;
            if (count <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(range));
            }
            DeterministicMemory<T> deterministicSpan = new(count);
            MemoryManager.Memcpy(deterministicSpan.DataPointer, DataPointer + range.Start.Value, count * sizeof(T));
            return deterministicSpan;
        }
    }

    public DeterministicMemory(Size_T count)
    {
        ByteSize = count * sizeof(T);
        Count = count;
        BasePointer = MemoryManager.Calloc(count, sizeof(T));
        WillFreeAllocatedMemory = true;
        NativeHandle = new IntPtr(DataPointer);
    }

    private DeterministicMemory(T* basePointer, int byteSize, bool willFreeAllocatedMemory)
    {
        ByteSize = byteSize;
        Count = byteSize / sizeof(T);
        BasePointer = basePointer;
        NativeHandle = new IntPtr(DataPointer);
        WillFreeAllocatedMemory = willFreeAllocatedMemory;
    }

    public readonly void Dispose()
    {
        if (DataPointer != null)
        {
            ZeroMemory();
            if (WillFreeAllocatedMemory)
            {
                MemoryManager.Free(DataPointer);
            }
        }
    }

    public Span<T> AsSpan() => new(DataPointer, Count);

    public void Free() => Dispose();

    public readonly MemoryAccess<T> GetAccess() => new(DataPointer, Count);

    readonly IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();

    public readonly void ZeroMemory() => Unsafe.InitBlockUnaligned(DataPointer, 0, ByteSize);

    public DeterministicMemory<TNew> As<TNew>() where TNew : unmanaged =>
        new((TNew*)DataPointer, ByteSize, false);

    public static DeterministicMemory<T> Allocate(Size_T count) => new(count);

    public readonly MemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => 
        new((TAs*)DataPointer, ByteSize / sizeof(TAs));

    readonly IMemoryAccess<TAs> IUnmanaged.GetAccess<TAs>() => GetAccess<TAs>();

    public static DeterministicMemory<T> ProtectOnly(void* buffer, Size_T byteSize) => 
        new((T*)buffer, byteSize, false);

    public static DeterministicMemory<T> CreateFrom(ReadOnlySpan<T> data)
    {
        DeterministicMemory<T> span = Allocate(data.Length);
        Span<T> destination = new(span.DataPointer, span.Count);
        data.CopyTo(destination);
        return span;
    }
}
