using System;

namespace PrySec.Base.Memory
{
    public unsafe interface IUnmanaged<T> : IDisposable where T : unmanaged
    {
        void Free();

        T* BasePointer { get; }

        int Size { get; }

        Size_T ByteSize { get; }

        IMemoryAccess<T> GetAccess();
    }
}