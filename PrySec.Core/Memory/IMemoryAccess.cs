using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Core.Memory;

public unsafe interface IMemoryAccess<T> : IDisposable where T : unmanaged
{
    /// <summary>
    /// Points to the start of the client-usable memory region of this resource.
    /// </summary>
    public T* Pointer { get; }

    /// <summary>
    /// The number of <typeparamref name="T"/> elements that fit in the client-usable memory region of this resource.
    /// </summary>
    public int Count { get; }

    public T this[int index]
    {
        get => Pointer[index];
        set => Pointer[index] = value;
    }

    /// <summary>
    /// The size in bytes of the client-usable memory region of this resource.
    /// </summary>
    public Size_T ByteSize { get; }

    /// <summary>
    /// Gets an <see cref="UnsafeReference{T}"/> instance describing the underlying client-usable memory region of this resource.
    /// </summary>
    public UnsafeReference<T> GetUnsafeReference() => new(Pointer, Count);

    public void ZeroMemory();

    public Span<T> AsSpan();
}
