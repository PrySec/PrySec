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
            Handle = Marshal.AllocHGlobal(ByteSize);
            BasePointer = (T*)Handle;
            Size = size;
        }

        public void Dispose()
        {
            if (Handle != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Handle);
                Handle = IntPtr.Zero;
                GC.SuppressFinalize(this);
            }
        }

        public void Free() => Dispose();
    }
}