using PrySec.Base.Memory;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashs
{
    public interface IHashFunctionScp
    {
        IUnmanaged<byte> ComputeHash<T>(IUnmanaged<T> memory) where T : unmanaged;
    }
}
