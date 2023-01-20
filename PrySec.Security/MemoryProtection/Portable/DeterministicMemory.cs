using PrySec.Core;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives;
using System;
using System.Runtime.CompilerServices;
using System.Xml.Linq;

namespace PrySec.Security.MemoryProtection.Portable;

public unsafe readonly struct DeterministicMemory<T> : IProtectedMemoryFactory<DeterministicMemory<T>, T> where T : unmanaged
{
    public readonly int Count { get; }

    public readonly Size_T ByteSize { get; }

    public readonly T* BasePointer { get; }

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
            int size = range.End.Value - range.Start.Value;
            if (size <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(range));
            }
            DeterministicMemory<T> deterministicSpan = new(size);
            Unsafe.CopyBlockUnaligned(deterministicSpan.BasePointer, BasePointer + range.Start.Value, (uint)size);
            return deterministicSpan;
        }
    }

    public DeterministicMemory(Size_T count)
    {
        ByteSize = count * sizeof(T);
        Count = count;
        BasePointer = (T*)MemoryManager.Calloc(count, sizeof(T));
        WillFreeAllocatedMemory = true;
        NativeHandle = new IntPtr(BasePointer);
    }

    private DeterministicMemory(T* basePointer, int byteSize, bool willFreeAllocatedMemory)
    {
        ByteSize = byteSize;
        Count = byteSize / sizeof(T);
        BasePointer = basePointer;
        NativeHandle = new IntPtr(BasePointer);
        WillFreeAllocatedMemory = willFreeAllocatedMemory;
    }

    public readonly void Dispose()
    {
        if (BasePointer != null)
        {
            ZeroMemory();
            if (WillFreeAllocatedMemory)
            {
                MemoryManager.Free(BasePointer);
            }
        }
    }

    public Span<T> AsSpan() => new(BasePointer, Count);

    public void Free() => Dispose();

    public readonly MemoryAccess<T> GetAccess() => new(BasePointer, Count);

    readonly IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();

    public readonly void ZeroMemory() => Unsafe.InitBlockUnaligned(BasePointer, 0, ByteSize);

    public DeterministicMemory<TNew> As<TNew>() where TNew : unmanaged =>
        new((TNew*)BasePointer, ByteSize, false);

    public static DeterministicMemory<T> Allocate(Size_T count) => new(count);

    public readonly MemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => 
        new((TAs*)BasePointer, ByteSize / sizeof(TAs));

    readonly IMemoryAccess<TAs> IUnmanaged.GetAccess<TAs>() => GetAccess<TAs>();

    public static DeterministicMemory<T> ProtectOnly(void* buffer, Size_T byteSize) => 
        new((T*)buffer, byteSize, false);

    public static DeterministicMemory<T> CreateFrom(ReadOnlySpan<T> data)
    {
        DeterministicMemory<T> span = Allocate(data.Length);
        Span<T> destination = new(span.BasePointer, span.Count);
        data.CopyTo(destination);
        return span;
    }
}
