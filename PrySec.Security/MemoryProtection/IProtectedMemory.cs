using PrySec.Core.Memory;
using System;

namespace PrySec.Security.MemoryProtection
{
    public interface IProtectedMemory<T> : IUnmanaged<T> where T : unmanaged
    {
        IntPtr NativeHandle { get; }

        void ZeroMemory();
    }

    public interface IProtectedMemoryFactory<TProtectedMemoryFactory, TData> : IProtectedMemory<TData>, IUnmanaged<TProtectedMemoryFactory, TData>
        where TProtectedMemoryFactory : IProtectedMemoryFactory<TProtectedMemoryFactory,TData>
        where TData : unmanaged
    {
    }
}