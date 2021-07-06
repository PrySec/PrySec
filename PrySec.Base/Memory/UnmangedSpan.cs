using System;

namespace PrySec.Base.Memory
{
    public unsafe readonly struct UnmangedSpan<T> : IUnmanaged<T> where T : unmanaged
    {
        public T* BasePointer => throw new NotImplementedException();

        public IntPtr Handle => throw new NotImplementedException();

        public int Size => throw new NotImplementedException();

        public void Dispose()
        {
            throw new NotImplementedException();
        }

        public void Free()
        {
            throw new NotImplementedException();
        }

        public IMemoryAccess<T> GetAccess()
        {
            throw new NotImplementedException();
        }
    }
}