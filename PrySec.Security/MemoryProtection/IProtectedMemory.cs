using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Security.MemoryProtection;

public interface IProtectedMemory<T> : IUnmanaged<T> where T : unmanaged
{
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
    internal void* BasePointerInternal { get; }

    internal void ZeroMemory();
}

internal enum ProtectionState
{
    Protected,
    Unprotected
}