using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Security.MemoryProtection;

public interface IProtectedMemory<T> : IUnmanaged<T> where T : unmanaged
{
    /// <summary>
    /// A native handle to the base address of this protected memory region.
    /// </summary>
    nint NativeHandle { get; }

    Size_T NativeByteSize { get; }
}

public interface IProtectedMemoryFactory<TProtectedMemoryFactory, TData> : IProtectedMemory<TData>, IUnmanaged<TProtectedMemoryFactory, TData>
    where TProtectedMemoryFactory : IProtectedMemoryFactory<TProtectedMemoryFactory,TData>
    where TData : unmanaged
{
}

internal interface IProtectedResource
{
    internal ProtectionState State { get; }

    internal void Protect();

    internal void Unprotect();
}

internal unsafe interface IProtectedMemoryProxy : IUnmanaged, IProtectedResource
{
    internal void ZeroMemory();
}

internal unsafe interface IProtectedMemoryProxy<TData> : IProtectedMemoryProxy, IProtectedMemory<TData> where TData : unmanaged
{
}

internal enum ProtectionState : uint
{
    Protected = 0,
    Unprotected = ~0u
}