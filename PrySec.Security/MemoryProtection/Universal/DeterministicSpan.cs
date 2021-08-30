using PrySec.Base;
using PrySec.Base.Memory;
using PrySec.Base.Memory.MemoryManagement;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.MemoryProtection.Universal
{
    public unsafe readonly struct DeterministicSpan<T> : IProtectedMemory<T> where T : unmanaged
    {
        public readonly int Size { get; }

        public readonly int ByteSize { get; }

        public readonly T* BasePointer { get; }

        public readonly IntPtr NativeHandle { get; }

        public DeterministicSpan(int size)
        {
            ByteSize = size * sizeof(T);
            Size = size;
            BasePointer = MemoryManager.Calloc<T>(size);
            NativeHandle = new IntPtr(BasePointer);
        }

        private DeterministicSpan(int byteSize, T* basePointer)
        {
            ByteSize = byteSize;
            Size = byteSize / sizeof(T);
            BasePointer = basePointer;
            NativeHandle = new IntPtr(BasePointer);
        }

        public readonly void Dispose()
        {
            if (BasePointer != Pointer.NULL)
            {
                ZeroMemory();
                MemoryManager.Free(BasePointer);
                GC.SuppressFinalize(this);
            }
        }

        public Span<T> AsSpan() => new(BasePointer, Size);

        public void Free() => Dispose();

        public readonly MemoryAccess<T> GetAccess() => new(BasePointer, Size);

        readonly IMemoryAccess<T> IUnmanaged<T>.GetAccess() => GetAccess();

        public readonly void ZeroMemory() => new Span<byte>(BasePointer, ByteSize).Fill(0x0);

        public DeterministicSpan<TNew> CastAs<TNew>() where TNew : unmanaged =>
            new(ByteSize, (TNew*)BasePointer);
    }
}
