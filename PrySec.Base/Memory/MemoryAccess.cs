namespace PrySec.Base.Memory
{
    public unsafe readonly struct MemoryAccess<T> : IMemoryAccess<T> where T : unmanaged
    {
        public MemoryAccess(T* ptr, int size)
        {
            Pointer = ptr;
            Size = size;
        }

        public readonly T* Pointer { get; }

        public readonly int Size { get; }

        public readonly void Dispose()
        {
        }
    }
}