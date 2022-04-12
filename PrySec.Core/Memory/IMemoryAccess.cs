using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Core.Memory;

public unsafe interface IMemoryAccess<T> : IDisposable where T : unmanaged
{
    public T* Pointer { get; }

    public int Count { get; }

    public Size_T ByteSize { get; }

    public UnsafeReference<T> GetUnsafeReference() => new(Pointer, Count);
}
