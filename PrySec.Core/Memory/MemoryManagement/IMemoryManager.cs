using PrySec.Core.NativeTypes;

namespace PrySec.Core.Memory.MemoryManagement;

public unsafe interface IMemoryManager
{
    static abstract void Free(void* memory);

    static abstract void* Malloc(Size_T size);

    static abstract void* Calloc(Size_T count, Size_T size);

    static abstract void* Realloc(void* previous, Size_T newSize);

    T* Calloc<T>(Size_T count) where T : unmanaged;

    T* Realloc<T>(T* previous, Size_T newCount) where T : unmanaged;

    bool SupportsAllocationTracking { get; }
}