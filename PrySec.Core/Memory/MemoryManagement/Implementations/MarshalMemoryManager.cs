using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Core.Memory.MemoryManagement.Implementations;

public readonly struct MarshalMemoryManager : IMemoryManager
{
    public bool SupportsAllocationTracking => false;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void* Calloc(Size_T count, Size_T size)
    {
        Size_T byteSize = count * size;
        void* ptr = Marshal.AllocHGlobal(byteSize).ToPointer();
        MemoryManager.ZeroMemory(ptr, byteSize);
        return ptr;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Free(void* memory) =>
        Marshal.FreeHGlobal(new IntPtr(memory));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void* Malloc(Size_T size) =>
        Marshal.AllocHGlobal(size).ToPointer();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void* Realloc(void* previous, Size_T newSize) =>
        Marshal.ReAllocHGlobal(new IntPtr(previous), (IntPtr)newSize).ToPointer();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe T* Calloc<T>(Size_T count) where T : unmanaged
    {
        Size_T byteSize = count * sizeof(T);
        T* ptr = (T*)Marshal.AllocHGlobal(byteSize);
        MemoryManager.ZeroMemory(ptr, byteSize);
        return ptr;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public unsafe T* Realloc<T>(T* previous, Size_T newCount) where T : unmanaged =>
        (T*)Marshal.ReAllocHGlobal(new IntPtr(previous), (IntPtr)newCount);
}