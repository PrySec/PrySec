using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Core.Memory;

/// <summary>
/// Basically a <see cref="Span{T}"/>, but with pointers.
/// </summary>
/// <typeparam name="T"></typeparam>
public unsafe readonly ref struct UnsafeReference<T> where T : unmanaged
{
    public readonly T* Pointer;

    public readonly int Size;

    public readonly Size32_T ByteSize;

    public UnsafeReference(T* ptr, int size)
    {
        Pointer = ptr;
        Size = size;
        ByteSize = size * sizeof(T);
    }

    public void SetZero() => new Span<byte>(Pointer, ByteSize).Clear();
}