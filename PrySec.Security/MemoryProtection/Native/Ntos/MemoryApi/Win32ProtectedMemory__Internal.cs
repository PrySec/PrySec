using PrySec.Core.Extensions;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Core.Native;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Portable.ProtectedMemory;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;

internal unsafe class Win32ProtectedMemory__Internal<T> : IProtectedMemoryFactory<Win32ProtectedMemory__Internal<T>, T>, IProtectedMemoryProxy<T>, IGuardedMemoryRegion where T : unmanaged
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
            RestrictedAreaByteSize = OS.RoundToNextPageSize(ByteSize);
            NativeByteSize = RestrictedAreaByteSize + (2 * OS.PageSize);
            void* nativeAllocationBase = NativeMemory.AlignedAlloc(NativeByteSize, OS.PageSize);
            _ = MemoryManager.TryRegisterExternalAllocation(nativeAllocationBase, NativeByteSize);
            NativeHandle = new nint(nativeAllocationBase);
            BasePointer = (byte*)nativeAllocationBase + OS.PageSize;
            FrontGuardHandle = NativeHandle;
            RearGuardHandle = NativeHandle + NativeByteSize - OS.PageSize;
            MemoryApiNativeShim.VirtualProtect(FrontGuardHandle, OS.PageSize, MemoryProtection.PAGE_READONLY | MemoryProtection.PAGE_GUARD);
            MemoryApiNativeShim.VirtualProtect(RearGuardHandle, OS.PageSize, MemoryProtection.PAGE_READONLY | MemoryProtection.PAGE_GUARD);
            this.As<IProtectedResource>().Protect();
            PageProtectionStateWatchdog.Monitor(this);
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

    nint IGuardedMemoryRegion.FrontGuardHandle => FrontGuardHandle;

    nint IGuardedMemoryRegion.RearGuardHandle => RearGuardHandle;

    nint IGuardedMemoryRegion.BaseHandle => BaseHandle;

    public int Count { get; }

    public Size_T ByteSize { get; }

    private volatile uint _isProtected = (uint)ProtectionState.Unprotected;

    private volatile uint _accessCount = 0;

    internal ProtectionState State => (ProtectionState)_isProtected;

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
            PageProtectionStateWatchdog.Disregard(this);
            this.As<IProtectedMemoryProxy>().Unprotect();
            MemoryManager.ZeroMemory(BasePointer, ByteSize);
            MemoryApiNativeShim.VirtualProtect(FrontGuardHandle, OS.PageSize, MemoryProtection.PAGE_READWRITE);
            MemoryApiNativeShim.VirtualProtect(RearGuardHandle, OS.PageSize, MemoryProtection.PAGE_READWRITE);
            void* nativeAllocationBase = NativeHandle.ToPointer();
            NativeMemory.AlignedFree(nativeAllocationBase);
            _ = MemoryManager.TryUnregisterExternalAllocation(nativeAllocationBase);
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
            Interlocked.Exchange(ref _isProtected, (uint)ProtectionState.Protected);
        }
    }

    void IProtectedResource.Unprotect()
    {
        if (!disposedValue && Interlocked.CompareExchange(ref _isProtected, (uint)ProtectionState.Unprotected, (uint)ProtectionState.Protected) == (uint)ProtectionState.Protected)
        {
            while (_accessCount > 0)
            {
                Thread.SpinWait(1);
            }
            MemoryApiNativeShim.VirtualProtect(BaseHandle, RestrictedAreaByteSize, MemoryProtection.PAGE_READWRITE);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsGuardPage(nint handle, MEMORY_BASIC_INFORMATION* context, out string error)
    {
        error = "guard page access detected!";
        return (MemoryApiNativeShim.QueryPageInfo(handle, context) & MemoryProtection.PAGE_GUARD) == MemoryProtection.PAGE_GUARD;
    }

    bool IGuardedMemoryRegion.OnFrontGuardHandleWatchdogValidation(nint handle, void* context, out string error) =>
        IsGuardPage(handle, (MEMORY_BASIC_INFORMATION*)context, out error);

    bool IGuardedMemoryRegion.OnRearGuardHandleWatchdogValidation(nint handle, void* context, out string error) =>
        IsGuardPage(handle, (MEMORY_BASIC_INFORMATION*)context, out error);

    bool IGuardedMemoryRegion.OnBaseHandleWatchdogValidation(nint handle, void* context, [NotNullWhen(false)] out string? error)
    {
        if (_isProtected == (uint)ProtectionState.Protected)
        {
            using ProtectionStateWatchdogAccess access = new(this);
            if (_isProtected == (uint)ProtectionState.Protected && MemoryApiNativeShim.QueryPageInfo(handle, (MEMORY_BASIC_INFORMATION*)context) != MemoryProtection.PAGE_NOACCESS)
            {
                error = "PAGE_NOACCESS was lifted!";
                return false;
            }
        }
        error = null;
        return true;
    }

    void IGuardedMemoryRegion.OnWatchdogFailure() => Dispose();

    private readonly struct ProtectionStateWatchdogAccess : IDisposable
    {
        private readonly Win32ProtectedMemory__Internal<T> _parent;

        public ProtectionStateWatchdogAccess(Win32ProtectedMemory__Internal<T> parent)
        {
            _parent = parent;
            Interlocked.Increment(ref _parent._accessCount);
        }

        public void Dispose() => Interlocked.Decrement(ref _parent._accessCount);
    }
}
