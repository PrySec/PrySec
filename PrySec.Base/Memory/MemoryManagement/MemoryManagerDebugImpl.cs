using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace PrySec.Base.Memory.MemoryManagement
{
    internal unsafe class MemoryManagerDebugImpl : IMemoryManagerImpl
    {
        private readonly ThreadLocal<Dictionary<IntPtr, (int, string)>> _allocations = new();

        public MemoryManagerDebugImpl()
        {
            _allocations.Value = new Dictionary<IntPtr, (int, string)>();
        }

        public AllocationSnapshot GetAllocationSnapshotForThread()
        {
            AllocationSnapshot snapshot = new(_allocations.Value!.Values.ToList());
            _allocations.Value!.Clear();
            return snapshot;
        }

        public T* Calloc<T>(int c) where T : unmanaged
        {
            if (c == 0)
            {
                return (T*)Pointer.NULL;
            }
            int allocatedSize = c * sizeof(T);
            IntPtr handle = Marshal.AllocHGlobal(allocatedSize);
            _allocations.Value!.Add(handle, (allocatedSize, GetStackTrace()));
            return (T*)handle;
        }

        public void Free(void* ptr)
        {
            if (ptr != Pointer.NULL)
            {
                IntPtr handle = new(ptr);
                _allocations.Value!.Remove(handle);
                Marshal.FreeHGlobal(handle);
            }
        }

        public void* Malloc(int cb)
        {
            if (cb == 0)
            {
                return Pointer.NULL;
            }
            IntPtr handle = Marshal.AllocHGlobal(cb);
            _allocations.Value!.Add(handle, (cb, GetStackTrace()));
            return (void*)handle;
        }

        private static string GetStackTrace() => new StackTrace().ToString();
    }
}