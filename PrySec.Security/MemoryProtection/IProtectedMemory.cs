using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Security.MemoryProtection;

public interface IProtectedMemory<T> : IUnmanaged<T> where T : unmanaged
{
    nint NativeHandle { get; }

    Size_T NativeByteSize { get; }

    void ZeroMemory();
}

public interface IProtectedMemoryFactory<TProtectedMemoryFactory, TData> : IProtectedMemory<TData>, IUnmanaged<TProtectedMemoryFactory, TData>
    where TProtectedMemoryFactory : IProtectedMemoryFactory<TProtectedMemoryFactory,TData>
    where TData : unmanaged
{
}

public interface IRequireManualAccess
{
    internal ProtectionState State { get; set; }

    internal void Protect();

    internal void Unprotect();
}

internal enum ProtectionState
{
    Protected,
    Unprotected
}