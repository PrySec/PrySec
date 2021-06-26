using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Base.Memory.MemoryManagement
{
    internal unsafe class MemoryManagerImpl : IMemoryManagerImpl
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public T* Calloc<T>(int c) where T : unmanaged =>
            (T*)Marshal.AllocHGlobal(c * sizeof(T));

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public void Free(void* ptr) =>
            Marshal.FreeHGlobal(new IntPtr(ptr));

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public void* Malloc(int cb) =>
            (void*)Marshal.AllocHGlobal(cb);
    }
}