using System;

namespace PrySec.Base.Memory
{
    public unsafe interface IUnmanaged<T> : IDisposable where T : unmanaged
    {
        void Free();

        T* BasePointer { get; }

        IntPtr Handle { get; }

        int Size { get; }

        IMemoryAccess<T> GetAccess();
    }
}