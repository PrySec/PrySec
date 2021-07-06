using System;

namespace PrySec.Base.Memory
{
    public unsafe interface IMemoryAccess<T> : IDisposable where T : unmanaged
    {
        public T* Pointer { get; }

        public int Size { get; }
    }
}