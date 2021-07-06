using PrySec.Base.Memory.MemoryManagement;
using System;
using System.Runtime.InteropServices;

namespace PrySec.Base.Memory
{
    public unsafe class UnmanagedMemory<T> : IUnmanaged<T> where T : unmanaged
    {
        public IntPtr Handle { get; private set; }

        public int Size { get; }

        public int ByteSize { get; }

        public T* BasePointer { get; private set; }

        public UnmanagedMemory(int size)
        {
            ByteSize = size * sizeof(T);
            BasePointer = MemoryManager.Calloc<T>(size);
            Handle = new IntPtr(BasePointer);
            Size = size;
        }

        public void Dispose()
        {
            if (Handle != IntPtr.Zero)
            {
                MemoryManager.Free(BasePointer);
                Handle = IntPtr.Zero;
                GC.SuppressFinalize(this);
            }
        }

        public void Free() => Dispose();

        public MemoryAccess<T> GetAccess() => new(BasePointer, Size);

        IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();
    }
}