﻿using PrySec.Core.NativeTypes;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;

namespace PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;

public readonly unsafe struct AllocationTracker<TMemoryManager> : IMemoryManager, IAllocationTracker where TMemoryManager : struct, IMemoryManager
{
    private static readonly ConcurrentDictionary<nuint, Allocation> _allocations = new();

    private readonly TMemoryManager _impl = new();

    public AllocationTracker()
    {
    }

    public bool SupportsAllocationTracking => true;

    public static void* Calloc(Size_T count, Size_T size)
    {
        void* p = TMemoryManager.Calloc(count, size);
        Allocation allocation = new(new IntPtr(p), (ulong)count * size, new StackTrace(1));
        _allocations.TryAdd((nuint)p, allocation);
        return p;
    }

    public static void Free(void* memory)
    {
        TMemoryManager.Free(memory);
        _allocations.TryRemove((nuint)memory, out _);
    }

    public static void* Malloc(Size_T size)
    {
        void* p = TMemoryManager.Malloc(size);
        Allocation allocation = new(new IntPtr(p), size, new StackTrace(1));
        _allocations.TryAdd((nuint)p, allocation);
        return p;
    }

    public static void* Realloc(void* previous, Size_T newSize)
    {
        _allocations.TryRemove((nuint)previous, out _);
        void* p = TMemoryManager.Realloc(previous, newSize);
        Allocation allocation = new(new IntPtr(p), newSize, new StackTrace(1));
        _allocations.TryAdd((nuint)p, allocation);
        return p;
    }

    public T* Calloc<T>(Size_T count) where T : unmanaged
    {
        T* p = _impl.Calloc<T>(count);
        Allocation allocation = new(new IntPtr(p), count * (ulong)sizeof(T), new StackTrace(1));
        _allocations.TryAdd((nuint)p, allocation);
        return p;
    }

    public void Clear() => _allocations.Clear();

    public AllocationSnapshot GetAllocationSnapshot(bool reset = false)
    {
        Allocation[] allocations = _allocations.Values.ToArray();
        if (reset)
        {
            Clear();
        }
        return new AllocationSnapshot(allocations);
    }

    public T* Realloc<T>(T* previous, Size_T newCount) where T : unmanaged
    {
        _allocations.TryRemove((nuint)previous, out _);
        T* p = _impl.Realloc(previous, newCount);
        Allocation allocation = new(new IntPtr(p), newCount * (ulong)sizeof(T), new StackTrace(1));
        _allocations.TryAdd((nuint)p, allocation);
        return p;
    }

    public void RegisterExternalAllocation(void* handle, nuint size)
    {
        Allocation allocation = new(new IntPtr(handle), size, new StackTrace(1));
        _allocations.TryAdd((nuint)handle, allocation);
    }

    public void UnregisterExternalAllocation(void* handle) => _allocations.TryRemove(new UIntPtr(handle), out _);
}