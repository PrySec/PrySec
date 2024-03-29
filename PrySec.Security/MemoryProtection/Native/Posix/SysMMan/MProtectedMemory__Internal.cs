﻿using PrySec.Core.Extensions;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Native;
using PrySec.Core.Native.UnixLike.Procfs;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Portable.ProtectedMemory;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Threading;

namespace PrySec.Security.MemoryProtection.Native.Posix.SysMMan;

internal unsafe class MProtectedMemory__Internal<T> : IProtectedMemoryFactory<MProtectedMemory__Internal<T>, T>, IProtectedMemoryProxy<T>, IMonitoredMemoryRegion where T : unmanaged
{
    private bool disposedValue = false;

    private readonly ISysMManAccessValidator _validator;

    private protected MProtectedMemory__Internal(Size_T count)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "count must be a non-negative integer.");
        }
        _validator = OS.IsPlatform(OSPlatform.OSX)
            ? default(MacOSAccessValidator)
            : default(ProcfsAccessValidator);
        if (count != 0)
        {
            Count = count;
            ByteSize = count * sizeof(T);
            NativeByteSize = OS.RoundToNextPageSize(ByteSize);
            BasePointer = NativeMemory.AlignedAlloc(NativeByteSize, OS.PageSize);
            _ = MemoryManager.TryRegisterExternalAllocation(BasePointer, NativeByteSize);
            NativeHandle = new nint(BasePointer);
            SysMManNativeShim.MLock(NativeHandle, NativeByteSize);
            this.As<IProtectedResource>().Protect();
            PageProtectionStateWatchdog.Monitor(this);
        }
    }

    public MProtectedMemory__Internal<T> this[Range range] => throw new NotSupportedException();

    public Size_T NativeByteSize { get; }

    public nint NativeHandle { get; private set; }

    public unsafe void* BasePointer { get; private set; }

    public unsafe T* DataPointer => (T*)BasePointer;

    internal nint BaseHandle => (nint)BasePointer;

    public int Count { get; }

    public Size_T ByteSize { get; }

    private volatile uint _isProtected = (uint)ProtectionState.Unprotected;

    private volatile uint _accessCount = 0;

    internal ProtectionState State => (ProtectionState)_isProtected;

    ProtectionState IProtectedResource.State => State;

    nint IMonitoredMemoryRegion.BaseHandle => BaseHandle;

    public static MProtectedMemory__Internal<T> Allocate(Size_T count) => new(count);

    public static MProtectedMemory__Internal<T> CreateFrom(ReadOnlySpan<T> data)
    {
        MProtectedMemory__Internal<T> memory = Allocate(data.Length);
        using (IMemoryAccess<T> access = memory.GetAccess())
        {
            data.CopyTo(access.AsSpan());
        }
        return memory;
    }

    public void Free() => Dispose();

    public IMemoryAccess<T> GetAccess() => new ProtectedMemoryAccess<MProtectedMemory__Internal<T>, T>(this);

    public IMemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => new ProtectedMemoryAccess<MProtectedMemory__Internal<T>, TAs>(this);

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
            SysMManNativeShim.MUnlock(NativeHandle, NativeByteSize);
            void* nativeAllocationBase = NativeHandle.ToPointer();
            NativeMemory.AlignedFree(nativeAllocationBase);
            _ = MemoryManager.TryUnregisterExternalAllocation(nativeAllocationBase);
            NativeHandle = 0;
            BasePointer = null;
            disposedValue = true;
        }
    }

    ~MProtectedMemory__Internal()
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
            SysMManNativeShim.MProtect(BaseHandle, NativeByteSize, MemoryProtection.PROT_NONE);
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
            SysMManNativeShim.MProtect(BaseHandle, NativeByteSize, MemoryProtection.PROT_READ | MemoryProtection.PROT_WRITE);
        }
    }

    bool IMonitoredMemoryRegion.OnBaseHandleWatchdogValidation(nint handle, void* context, [NotNullWhen(false)] out string? error)
    {
        if (_isProtected == (uint)ProtectionState.Protected)
        {
            using ProtectionStateWatchdogAccess access = new(this);

            if (_isProtected == (uint)ProtectionState.Protected && !_validator.ValidateNoAccess(handle, context))
            {
                error = "PROT_NONE was lifted!";
                return false;
            }
        }
        error = null;
        return true;
    }

    void IMonitoredMemoryRegion.OnWatchdogFailure() => Dispose();

    private readonly struct ProtectionStateWatchdogAccess : IDisposable
    {
        private readonly MProtectedMemory__Internal<T> _parent;

        public ProtectionStateWatchdogAccess(MProtectedMemory__Internal<T> parent)
        {
            _parent = parent;
            Interlocked.Increment(ref _parent._accessCount);
        }

        public void Dispose() => Interlocked.Decrement(ref _parent._accessCount);
    }
}

file readonly struct ProcfsAccessValidator : ISysMManAccessValidator
{
    private static readonly ThreadLocal<ProcfsMapsParser> _procfs = new(() => new ProcfsMapsParser(256));

    public unsafe bool ValidateNoAccess(nint handle, void* context)
    {
        ProcfsMemoryRegionInfo* info = (ProcfsMemoryRegionInfo*)context;
        return _procfs.Value?.TryVirtualQuery(handle, info, false) is true 
            && info->Permissions == ProcfsPermissions.NoAccess;
    }
}

file readonly struct MacOSAccessValidator : ISysMManAccessValidator
{
    public unsafe bool ValidateNoAccess(nint handle, void* context) => true;
}