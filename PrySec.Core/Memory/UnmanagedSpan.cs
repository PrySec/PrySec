using PrySec.Core.Memory.MemoryManagement;
using System;

namespace PrySec.Core.Memory;

public unsafe readonly ref struct UnmanagedSpan<T> where T : unmanaged
{
    public readonly IntPtr Handle;

    private readonly Span<T> _span;

    private readonly Span<byte> _byteSpan;

    public readonly int Length;

    public readonly int ByteSize;

    public readonly T* BasePointer;

    public UnmanagedSpan(int size)
    {
        Length = size;
        ByteSize = size * sizeof(T);
        Handle = (IntPtr)MemoryManager.Malloc(ByteSize);
        BasePointer = (T*)Handle;
        _span = new Span<T>(BasePointer, Length);
        _byteSpan = new Span<byte>(BasePointer, ByteSize);
    }

    public readonly Span<T> AsSpan() => _span;

    public readonly void ZeroMemory() => _byteSpan.Clear();

    public readonly void Memset(T value) => _span.Fill(value);

    public readonly void Free() => MemoryManager.Free(BasePointer);
}