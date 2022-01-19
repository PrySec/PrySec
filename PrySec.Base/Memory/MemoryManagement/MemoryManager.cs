using PrySec.Core.Memory.MemoryManagement.Implementations;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Core.Memory.MemoryManagement;

public static unsafe partial class MemoryManager
{
    static MemoryManager() => UseImplementation<NativeMemoryManager>();

    /// <summary>
    /// <see langword="void"/> Free(<see langword="void*"/> ptr);
    /// </summary>
    public static delegate*<void*, void> Free { get; private set; } = null;

    /// <summary>
    /// <see langword="void*"/> Malloc(<see cref="Size_T"/> byteSize);
    /// </summary>
    public static delegate*<Size_T, void*> Malloc { get; private set; } = null;

    /// <summary>
    /// <see langword="void*"/> Realloc(<see langword="void*"/> previous, <see cref="Size_T"/> newByteSize);
    /// </summary>
    public static delegate*<void*, Size_T, void*> Realloc { get; private set; } = null;

    /// <summary>
    /// <see langword="void*"/> Calloc(<see cref="Size_T"/> elementCount, <see cref="Size_T"/> elementSize);
    /// </summary>
    public static delegate*<Size_T, Size_T, void*> Calloc { get; private set; } = null;

    public static IMemoryManager Allocator { get; private set; } = null!;

    public static void UseImplementation<TImpl>() where TImpl : struct, IMemoryManager
    {
        Allocator = new TImpl();
        Free = &TImpl.Free;
        Malloc = &TImpl.Malloc;
        Realloc = &TImpl.Realloc;
        Calloc = &TImpl.Calloc;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static void ZeroMemory<T>(T* ptr, int elementCount) where T : unmanaged =>
        ZeroMemory((void*)ptr, elementCount * sizeof(T));

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static void ZeroMemory(void* ptr, int byteSize) =>
        new Span<byte>(ptr, byteSize).Fill(0);

    public static AllocationSnapshot? GetAllocationSnapshot(bool reset = false) => 
        Allocator is IAllocationTracker tracker 
        ? tracker.GetAllocationSnapshot(reset) 
        : null;
}