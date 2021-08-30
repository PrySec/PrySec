using PrySec.Base.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashs
{
    public static class HashExtensions
    {
        public static unsafe string ComputeHash(this IHashFunctionScp hashFunction, string input)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(input);
            using UnmanagedMemory<byte> memory = new(bytes);
            using IUnmanaged<byte> result = hashFunction.ComputeHash(memory);
            using IMemoryAccess<byte> access = result.GetAccess();
            ReadOnlySpan<byte> span = new(access.Pointer, access.Size);
            return Convert.ToHexString(span);
        }
    }
}
