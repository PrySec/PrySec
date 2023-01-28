using PrySec.Core.Extensions;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Core.NativeTypes;
using PrySec.Security.Cryptography.Crng;
using System;
using System.Runtime.InteropServices;

namespace PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;

internal unsafe class Win32ProtectedMemory__Internal<T> : IProtectedMemoryFactory<Win32ProtectedMemory__Internal<T>, T>, IProtectedMemoryProxy where T : unmanaged
{
    private bool disposedValue = false;

    private protected Win32ProtectedMemory__Internal(Size_T count)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "count must be a non-negative integer.");
        }
        if (count != 0)
        {
            Count = count;
            ByteSize = count * sizeof(T);
            // Guard page + data pages + guard page
            RestrictedAreaByteSize = MemoryApiNativeShim.RoundToNextPageSize(ByteSize);
            NativeByteSize = RestrictedAreaByteSize + 2 * MemoryApiNativeShim.PageSize;
            void* nativeAllocationBase = NativeMemory.AlignedAlloc(NativeByteSize, (nuint)MemoryApiNativeShim.PageSize);
            if (MemoryManager.Allocator.SupportsAllocationTracking && MemoryManager.Allocator is IAllocationTracker tracker)
            {
                tracker.RegisterExternalAllocation(nativeAllocationBase, NativeByteSize);
            }
            NativeHandle = new nint(nativeAllocationBase);
            BasePointer = (byte*)nativeAllocationBase + MemoryApiNativeShim.PageSize;
            FrontGuardHandle = NativeHandle;
            RearGuardHandle = NativeHandle + NativeByteSize - MemoryApiNativeShim.PageSize;
            MemoryApiNativeShim.VirtualLock(NativeHandle, NativeByteSize);
            MemoryApiNativeShim.VirtualProtect(FrontGuardHandle, MemoryApiNativeShim.PageSize, MemoryProtection.PAGE_GUARD);
            MemoryApiNativeShim.VirtualProtect(RearGuardHandle, MemoryApiNativeShim.PageSize, MemoryProtection.PAGE_GUARD);
            this.As<IProtectedResource>().Protect();
        }
    }

    public Win32ProtectedMemory__Internal<T> this[Range range] => throw new NotSupportedException();

    public Size_T NativeByteSize { get; }

    internal Size_T RestrictedAreaByteSize { get; }

    public nint NativeHandle { get; private set; }

    public unsafe void* BasePointer { get; private set; }

    public unsafe T* DataPointer => (T*)BasePointer;

    internal nint FrontGuardHandle { get; }

    internal nint RearGuardHandle { get; }

    internal nint BaseHandle => (nint)BasePointer;

    public int Count { get; }

    public Size_T ByteSize { get; }

    internal ProtectionState State { get; set; }

    ProtectionState IProtectedResource.State => State;

    public static Win32ProtectedMemory__Internal<T> Allocate(Size_T count) => new(count);

    public static Win32ProtectedMemory__Internal<T> CreateFrom(ReadOnlySpan<T> data)
    {
        Win32ProtectedMemory__Internal<T> memory = Allocate(data.Length);
        using (IMemoryAccess<T> access = memory.GetAccess())
        {
            data.CopyTo(access.AsSpan());
        }
        return memory;
    }

    public void Free() => Dispose();

    public IMemoryAccess<T> GetAccess() => new ProtectedMemoryAccess<Win32ProtectedMemory__Internal<T>, T>(this);

    public IMemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => new ProtectedMemoryAccess<Win32ProtectedMemory__Internal<T>, TAs>(this);

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                // TODO: dispose managed state (managed objects)
            }
            this.As<IProtectedMemoryProxy>().Unprotect();
            MemoryManager.ZeroMemory(BasePointer, ByteSize);
            MemoryApiNativeShim.VirtualProtect(FrontGuardHandle, MemoryApiNativeShim.PageSize, MemoryProtection.PAGE_READWRITE);
            MemoryApiNativeShim.VirtualProtect(RearGuardHandle, MemoryApiNativeShim.PageSize, MemoryProtection.PAGE_READWRITE);
            MemoryApiNativeShim.VirtualUnlock(NativeHandle, NativeByteSize);
            void* nativeAllocationBase = NativeHandle.ToPointer();
            NativeMemory.AlignedFree(nativeAllocationBase);
            if (MemoryManager.Allocator.SupportsAllocationTracking && MemoryManager.Allocator is IAllocationTracker tracker)
            {
                tracker.UnregisterExternalAllocation(nativeAllocationBase);
            }
            NativeHandle = 0;
            BasePointer = null;
            disposedValue = true;
        }
    }

    ~Win32ProtectedMemory__Internal()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }

    private protected virtual void ZeroMemory()
    {
        if (!disposedValue && State is ProtectionState.Unprotected)
        {
            MemoryManager.ZeroMemory(BasePointer, ByteSize);
        }
        else
        {
            throw new InvalidOperationException("Cannot zero memory while in protected state!");
        }
    }

    void IProtectedMemoryProxy.ZeroMemory() => ZeroMemory();

    void IProtectedResource.Protect()
    {
        if (!disposedValue && State is ProtectionState.Unprotected)
        {
            MemoryApiNativeShim.VirtualProtect(BaseHandle, RestrictedAreaByteSize, MemoryProtection.PAGE_NOACCESS);
            State = ProtectionState.Protected;
        }
    }

    void IProtectedResource.Unprotect()
    {
        if (!disposedValue && State is ProtectionState.Protected)
        {
            MemoryApiNativeShim.VirtualProtect(BaseHandle, RestrictedAreaByteSize, MemoryProtection.PAGE_READWRITE);
            State = ProtectionState.Unprotected;
        }
    }
}
