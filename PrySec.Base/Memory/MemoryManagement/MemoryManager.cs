using System.Runtime.CompilerServices;

namespace PrySec.Base.Memory.MemoryManagement
{
    public static unsafe class MemoryManager
    {
        private static IMemoryManagerImpl _memoryManagerImpl =
#if DEBUG
            new MemoryManagerDebugImpl();

#else
            new MemoryManagerImpl();
#endif

        public static void EnableDebugging(bool debuggingEnabled = false)
        {
            if (debuggingEnabled)
            {
                if (_memoryManagerImpl is not MemoryManagerDebugImpl)
                {
                    _memoryManagerImpl = new MemoryManagerDebugImpl();
                }
            }
            else
            {
                if (_memoryManagerImpl is not MemoryManagerImpl)
                {
                    _memoryManagerImpl = new MemoryManagerImpl();
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static void* Malloc(int cb) =>
            _memoryManagerImpl.Malloc(cb);

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static void Free(void* ptr) =>
            _memoryManagerImpl.Free(ptr);

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static T* Calloc<T>(int c) where T : unmanaged =>
            _memoryManagerImpl.Calloc<T>(c);

        public static AllocationSnapshot GetAllocationSnapshotForThread() =>
            (_memoryManagerImpl as MemoryManagerDebugImpl)?.GetAllocationSnapshotForThread() ?? new AllocationSnapshot(new());
    }
}