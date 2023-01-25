using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System;
using System.Text;

namespace PrySec.Security.Cryptography.Hashing;

public static class HashExtensions
{
    public static unsafe string ComputeHash(this IHashFunctionScp hashFunction, string input)
    {
        int byteCount = Encoding.UTF8.GetByteCount(input);
        byte* bytes = (byte*)MemoryManager.Malloc(byteCount);
        Span<byte> buffer = new(bytes, byteCount);
        _ = Encoding.UTF8.GetBytes(input, buffer);
        UnmanagedMemory<byte> memory = UnmanagedMemory<byte>.CreateFrom(buffer);
        MemoryManager.Free(bytes);
        using IUnmanaged<byte> result = hashFunction.ComputeHash<UnmanagedMemory<byte>, UnmanagedMemory<byte>>(ref memory);
        memory.Free();
        ReadOnlySpan<byte> span = new(result.DataPointer, result.Count);
        return Convert.ToHexString(span);
    }

    public static unsafe string ComputeHash(this IVariableLengthHashFunctionScp hashFunction, string input, Size_T digestSize)
    {
        int byteCount = Encoding.UTF8.GetByteCount(input);
        byte* bytes = (byte*)MemoryManager.Malloc(byteCount);
        Span<byte> buffer = new(bytes, byteCount);
        _ = Encoding.UTF8.GetBytes(input, buffer);
        UnmanagedMemory<byte> memory = UnmanagedMemory<byte>.CreateFrom(buffer);
        MemoryManager.Free(bytes);
        using IUnmanaged<byte> result = hashFunction.ComputeHash<UnmanagedMemory<byte>, UnmanagedMemory<byte>>(ref memory, digestSize);
        memory.Free();
        ReadOnlySpan<byte> span = new(result.DataPointer, result.Count);
        return Convert.ToHexString(span);
    }
}