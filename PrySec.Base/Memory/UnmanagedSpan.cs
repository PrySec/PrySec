using PrySec.Base.Memory.MemoryManagement;
using System;

namespace PrySec.Base.Memory
{
    public unsafe readonly struct UnmanagedSpan<T> : IUnmanaged<T> where T : unmanaged
    {
        public readonly IntPtr Handle { get; }

        public readonly int Size { get; }

        public readonly Size_T ByteSize { get; }

        public readonly T* BasePointer { get; }

        public UnmanagedSpan(int size)
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
                GC.SuppressFinalize(this);
            }
        }

        public void Free() => Dispose();

        public readonly MemoryAccess<T> GetAccess() => new(BasePointer, Size);

        readonly IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();
    }
}