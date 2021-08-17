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
            NativeHandle = Handle;
        }

        public override void Dispose()
        {
            if (Handle != IntPtr.Zero)
            {
                ZeroMemory();
                MemoryManager.Free(BasePointer);
                Handle = IntPtr.Zero;
                GC.SuppressFinalize(this);
            }
        }

        public void ZeroMemory() => new Span<byte>(BasePointer, ByteSize).Fill(0x0);
    }
}
