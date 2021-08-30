using PrySec.Base.Memory.MemoryManagement;
using System;
using System.Drawing;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Base.Memory
{
    public unsafe class UnmanagedMemory<T> : IUnmanaged<T> where T : unmanaged
    {
        public int Size { get; }

        public Size_T ByteSize { get;}

        public T* BasePointer { get; protected set; }

        public UnmanagedMemory(int size)
        {
            ByteSize = size * sizeof(T);
            Size = size;
            BasePointer = MemoryManager.Calloc<T>(size);
        }

        public UnmanagedMemory(T[] arr)
        {
            Size = arr.Length;
            ByteSize = Size * sizeof(T);
            BasePointer = MemoryManager.Calloc<T>(Size);
            if (arr.Length > 0)
            {
                fixed (T* pArr = arr)
                {
                    Unsafe.CopyBlockUnaligned(BasePointer, pArr, (uint)arr.Length);
                }
            }
        }

        public virtual void Dispose()
        {
            if (BasePointer != Pointer.NULL)
            {
                MemoryManager.Free(BasePointer);
                BasePointer = (T*)Pointer.NULL;
                GC.SuppressFinalize(this);
            }
        }

        public void Free() => Dispose();

        public virtual MemoryAccess<T> GetAccess() => new(BasePointer, Size);

        IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();

        public virtual Span<T> AsSpan() => new(BasePointer, Size);
    }
}