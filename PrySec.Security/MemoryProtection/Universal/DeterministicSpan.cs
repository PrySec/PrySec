using PrySec.Core;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives;
using System;
using System.Runtime.CompilerServices;
using System.Xml.Linq;

namespace PrySec.Security.MemoryProtection.Universal;

public unsafe readonly struct DeterministicSpan<T> : IProtectedMemoryFactory<DeterministicSpan<T>, T> where T : unmanaged
{
    public readonly int Count { get; }

    public readonly Size_T ByteSize { get; }

    public readonly T* BasePointer { get; }

    public readonly IntPtr NativeHandle { get; }

    public DeterministicSpan<T> this[Range range]
    {
        get
        {
            int size = range.End.Value - range.Start.Value;
            if (size <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(range));
            }
            DeterministicSpan<T> deterministicSpan = new(size);
            Unsafe.CopyBlockUnaligned(deterministicSpan.BasePointer, BasePointer + range.Start.Value, (uint)size);
            return deterministicSpan;
        }
    }

    public DeterministicSpan(Size_T count)
    {
        ByteSize = count * sizeof(T);
        Count = count;
        BasePointer = (T*)MemoryManager.Calloc(count, sizeof(T));
        NativeHandle = new IntPtr(BasePointer);
    }

    private DeterministicSpan(T* basePointer, int byteSize)
    {
        ByteSize = byteSize;
        Count = byteSize / sizeof(T);
        BasePointer = basePointer;
        NativeHandle = new IntPtr(BasePointer);
    }

    public readonly void Dispose()
    {
        if (BasePointer != null)
        {
            ZeroMemory();
            MemoryManager.Free(BasePointer);
            GC.SuppressFinalize(this);
        }
    }

    public Span<T> AsSpan() => new(BasePointer, Count);

    public void Free() => Dispose();

    public readonly MemoryAccess<T> GetAccess() => new(BasePointer, Count);

    readonly IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();

    public readonly void ZeroMemory() => new Span<byte>(BasePointer, ByteSize).Fill(0x0);

    public DeterministicSpan<TNew> As<TNew>() where TNew : unmanaged =>
        new((TNew*)BasePointer, ByteSize);

    public static DeterministicSpan<T> Allocate(Size_T count) => new(count);

    public readonly MemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => new((TAs*)BasePointer, ByteSize / sizeof(TAs));

    readonly IMemoryAccess<TAs> IUnmanaged.GetAccess<TAs>() => GetAccess<TAs>();

    public static DeterministicSpan<T> CreateFrom(ReadOnlySpan<T> data)
    {
        DeterministicSpan<T> span = Allocate(data.Length);
        Span<T> destination = new(span.BasePointer, span.Count);
        data.CopyTo(destination);
        return span;
    }
}
