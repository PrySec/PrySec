using PrySec.Base.Memory;
using System;

namespace PrySec.Security.MemoryProtection
{
    public interface IProtectedMemory<T> : IUnmanaged<T> where T : unmanaged
    {
        IntPtr NativeHandle { get; }

        void ZeroMemory();
    }
}