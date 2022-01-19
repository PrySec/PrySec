using PrySec.Core;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using System;

namespace PrySec.Security.MemoryProtection.Universal;

public unsafe class DeterministicMemory<T> : UnmanagedMemory<T>, IProtectedMemory<T> where T : unmanaged
{
    public IntPtr NativeHandle { get; }

    public DeterministicMemory(int count) : base(count)
    {
        NativeHandle = new IntPtr(BasePointer);
    }

    public override void Dispose()
    {
        if (BasePointer != null)
        {
            ZeroMemory();
            MemoryManager.Free(BasePointer);
            BasePointer = null;
            GC.SuppressFinalize(this);
        }
    }

    public void ZeroMemory()
    {
        if (BasePointer != null)
        {
            new Span<byte>(BasePointer, ByteSize).Fill(0x0);
        }
    }
}
