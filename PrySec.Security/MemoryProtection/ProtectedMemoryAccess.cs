using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.MemoryProtection;

internal unsafe readonly struct ProtectedMemoryAccess<TProtectedMemoryProxy, TData> : IMemoryAccess<TData>
    where TProtectedMemoryProxy : class, IProtectedResource, IProtectedMemoryProxy
    where TData : unmanaged
{
    private readonly TProtectedMemoryProxy _proxy;

    public ProtectedMemoryAccess(TProtectedMemoryProxy proxy)
    {
        _proxy = proxy;
        Pointer = (TData*)proxy.BasePointerInternal;
        Count = proxy.ByteSize / sizeof(TData);
        _proxy.Unprotect();
    }

    public unsafe TData* Pointer { get; }

    public int Count { get; }

    public Size_T ByteSize => _proxy.ByteSize;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe Span<TData> AsSpan() => new(Pointer, Count);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Dispose() => _proxy.Protect();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void ZeroMemory() => _proxy.ZeroMemory();
}
