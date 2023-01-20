using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Core.Memory;

public unsafe readonly struct MemoryAccess<T> : IMemoryAccess<T> where T : unmanaged
{
    public MemoryAccess(T* ptr, Size32_T count)
    {
        Pointer = ptr;
        Count = count;
        ByteSize = count * sizeof(T);
    }

    public readonly T* Pointer { get; }

    public readonly int Count { get; }

    public Size_T ByteSize { get; }

    public Span<T> AsSpan() => new(Pointer, Count);

    public readonly void Dispose()
    {
    }
}
