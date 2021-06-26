namespace PrySec.Base.Memory.MemoryManagement
{
    internal unsafe interface IMemoryManagerImpl
    {
        void* Malloc(int cb);

        T* Calloc<T>(int c) where T : unmanaged;

        void Free(void* ptr);
    }
}