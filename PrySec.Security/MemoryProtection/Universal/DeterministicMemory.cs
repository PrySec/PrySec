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
    public unsafe class DeterministicMemory<T> : UnmanagedMemory<T>, IProtectedMemory<T> where T : unmanaged
    {
        public IntPtr NativeHandle { get; }

        public DeterministicMemory(int count) : base(count)
        {
            NativeHandle = new IntPtr(BasePointer);
        }

        public override void Dispose()
        {
            if (BasePointer != Pointer.NULL)
            {
                ZeroMemory();
                MemoryManager.Free(BasePointer);
                BasePointer = (T*)Pointer.NULL;
                GC.SuppressFinalize(this);
            }
        }

        public void ZeroMemory()
        {
            if (BasePointer != Pointer.NULL)
            {
                new Span<byte>(BasePointer, ByteSize).Fill(0x0);
            }
        }
    }
}
