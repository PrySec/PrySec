using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Security.MemoryProtection;
public readonly struct ProtectedMemoryAccess<TProtectedMemory, TData> : IMemoryAccess<TData>
    where TProtectedMemory : class, IProtectedMemory<TData>, IRequireManualAccess
    where TData : unmanaged
{
    private readonly TProtectedMemory _memory;

    public ProtectedMemoryAccess(TProtectedMemory memory)
    {
        _memory = memory;
        _memory.Unprotect();
    }

    public unsafe TData* Pointer => _memory.BasePointer;

    public int Count => _memory.Count;

    public Size_T ByteSize => _memory.ByteSize;

    public unsafe Span<TData> AsSpan() => new(Pointer, Count);
    public void Dispose() => _memory.Protect();
}
