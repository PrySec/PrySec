using PrySec.Core.NativeTypes;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Core.Memory.MemoryManagement.Implementations;

public readonly unsafe struct NativeMemoryManager : IMemoryManager
{
    public bool SupportsAllocationTracking => false;

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static unsafe void* Calloc(Size_T count, Size_T size) => 
        NativeMemory.AllocZeroed(count * size);

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static unsafe void Free(void* memory) =>
        NativeMemory.Free(memory);

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static unsafe void* Malloc(Size_T size) =>
        NativeMemory.Alloc(size);

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static unsafe void* Realloc(void* previous, Size_T newSize) =>
        NativeMemory.Realloc(previous, newSize);

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public T* Calloc<T>(Size_T count) where T : unmanaged =>
        (T*)NativeMemory.AllocZeroed(count * sizeof(T));

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public T* Realloc<T>(T* previous, Size_T newCount) where T : unmanaged =>
        (T*)NativeMemory.Realloc(previous, newCount * sizeof(T));
}