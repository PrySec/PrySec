using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Base.Memory.MemoryManagement
{
    internal unsafe class MemoryManagerImpl : IMemoryManagerImpl
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public T* Calloc<T>(int c) where T : unmanaged
        {
            if (c == 0)
            {
                return (T*)Pointer.NULL;
            }
            return (T*)Marshal.AllocHGlobal(c * sizeof(T));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public void Free(void* ptr)
        {
            if (ptr != Pointer.NULL)
            {
                Marshal.FreeHGlobal(new IntPtr(ptr));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public void* Malloc(int cb)
        {
            if (cb == 0)
            {
                return Pointer.NULL;
            }
            return (void*)Marshal.AllocHGlobal(cb);
        }
    }
}