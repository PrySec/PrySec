using PrySec.Core.Memory;
using PrySec.Core.Native;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;
using PrySec.Security.MemoryProtection.Native.Posix.SysMMan;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Security.MemoryProtection.Portable.ProtectedMemory;

public unsafe class ProtectedMemory<T> : IProtectedMemoryFactory<ProtectedMemory<T>, T>, IProtectedMemoryProxy where T : unmanaged
{
    private readonly IProtectedMemoryProxy<T> _proxy;

    private ProtectedMemory(IProtectedMemoryProxy<T> proxy) => _proxy = proxy;

    private bool disposedValue = false;

    public Size_T ByteSize => _proxy.ByteSize;

    public void* BasePointer => _proxy.BasePointer;

    public nint NativeHandle => _proxy.NativeHandle;

    public Size_T NativeByteSize => _proxy.NativeByteSize;

    public T* DataPointer => _proxy.DataPointer;

    public int Count => _proxy.Count;

    ProtectionState IProtectedResource.State => _proxy.State;

    public ProtectedMemory<T> this[Range range] => throw new NotSupportedException();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public void Free() => Dispose();

    public static ProtectedMemory<T> Allocate(Size_T count) => new(0 switch
    {
        _ when OS.IsPlatform(OSPlatform.Windows) => Win32ProtectedMemory__Internal<T>.Allocate(count),
        _ => MProtectedMemory__Internal<T>.Allocate(count)
    });

    public static ProtectedMemory<T> CreateFrom(ReadOnlySpan<T> data) => new(0 switch
    {
        _ when OS.IsPlatform(OSPlatform.Windows) => Win32ProtectedMemory__Internal<T>.CreateFrom(data),
        _ => MProtectedMemory__Internal<T>.CreateFrom(data)
    });

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IMemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => _proxy.GetAccess<TAs>();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IMemoryAccess<T> GetAccess() => _proxy.GetAccess();

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                _proxy.Dispose();
            }
            disposedValue = true;
        }
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void IProtectedMemoryProxy.ZeroMemory() => _proxy.ZeroMemory();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void IProtectedResource.Protect() => _proxy.Protect();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    void IProtectedResource.Unprotect() => _proxy.Unprotect();
}