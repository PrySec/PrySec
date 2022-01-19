using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
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
        UnmanagedSpan<byte> memory = UnmanagedSpan<byte>.CreateFrom(buffer);
        MemoryManager.Free(bytes);
        using IUnmanaged<byte> result = hashFunction.ComputeHash<byte, UnmanagedSpan<byte>, UnmanagedSpan<byte>>(ref memory);
        memory.Free();
        ReadOnlySpan<byte> span = new(result.BasePointer, result.Count);
        return Convert.ToHexString(span);
    }
}