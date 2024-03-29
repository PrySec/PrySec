﻿using PrySec.Core.Exceptions;
using PrySec.Core.HwPrimitives;
using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Core.Memory;

public unsafe interface IUnmanaged : IDisposable
{
    void Free();

    /// <summary>
    /// The size in bytes of the client-usable memory region of this unmanaged allocation.
    /// </summary>
    Size_T ByteSize { get; }

    /// <summary>
    /// An untyped pointer to the base address of the client-usable memory region of this unmanaged allocation.
    /// </summary>
    void* BasePointer { get; }

    IMemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged;
}

public unsafe interface IUnmanaged<TData> : IUnmanaged where TData : unmanaged
{
    /// <summary>
    /// A typed version of the <see cref="IUnmanaged.BasePointer"/> to the base address of the client-usable memory region of this unmanaged allocation.
    /// </summary>
    TData* DataPointer { get; }

    int Count { get; }

    IMemoryAccess<TData> GetAccess();
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
        if (BinaryUtils.IsPowerOf2(sizeOfOther) && BinaryUtils.IsPowerOf2(sizeof(TData)))
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