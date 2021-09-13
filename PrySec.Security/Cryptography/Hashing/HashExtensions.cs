using PrySec.Base.Memory;
using System;
using System.Text;

namespace PrySec.Security.Cryptography.Hashing
{
    public static class HashExtensions
    {
        public static unsafe string ComputeHash(this IHashFunctionScp hashFunction, string input)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            IUnmanaged<byte> memory = new UnmanagedMemory<byte>(bytes);
            using IUnmanaged<byte> result = hashFunction.ComputeHash(ref memory);
            using IMemoryAccess<byte> access = result.GetAccess();
            ReadOnlySpan<byte> span = new(access.Pointer, access.Size);
            memory.Free();
            return Convert.ToHexString(span);
        }
    }
}