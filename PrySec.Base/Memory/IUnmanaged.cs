using PrySec.Core.Exceptions;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Core.Memory;

public unsafe interface IUnmanaged<TData> : IDisposable
    where TData : unmanaged
{
    void Free();

    TData* BasePointer { get; }

    int Count { get; }

    Size_T ByteSize { get; }

    IMemoryAccess<TData> GetAccess();

    IMemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged;
}

public unsafe interface IUnmanaged<TUnmanaged, TData> : IUnmanaged<TData>
    where TUnmanaged : IUnmanaged<TUnmanaged, TData>
    where TData : unmanaged
{
    static abstract TUnmanaged Allocate(Size_T count);

    static abstract TUnmanaged CreateFrom(ReadOnlySpan<TData> data);

    TUnmanaged this[Range range] { get; }

    virtual TOtherUnmanaged CopyTo<TOtherUnmanaged, TOtherData>()
        where TOtherUnmanaged : IUnmanaged<TOtherUnmanaged, TOtherData>
        where TOtherData : unmanaged
    {
        int sizeOfOther = sizeof(TOtherData);
        if (BinaryUtils.Ip2(sizeOfOther) && BinaryUtils.Ip2(sizeof(TData)))
        {
            int otherCount = ByteSize / sizeOfOther;
            TOtherUnmanaged other = TOtherUnmanaged.Allocate(otherCount);
            using IMemoryAccess<TData> access = GetAccess();
            using IMemoryAccess<TOtherData> otherAccess = other.GetAccess();
            Unsafe.CopyBlockUnaligned(access.Pointer, otherAccess.Pointer, ByteSize);
            return other;
        }
        ThrowHelper.ThrowInvalidCastException($"Cannot copy data of type {typeof(TData).Name} with size {sizeof(TData)} to {typeof(TOtherData).Name} with size {sizeof(TData)} because one of them wasn't a power of 2!");
        return default!;
    }
}