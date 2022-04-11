using PrySec.Core.Memory;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Blake3;
public unsafe partial class Blake3 : IHashFunctionScp
{
    public IUnmanaged<byte> ComputeHash<TData>(ref IUnmanaged<TData> input) where TData : unmanaged => throw new NotImplementedException();
    public TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> => throw new NotImplementedException();

    private void Blake3ContextInit(Blake3Context* self)
    {
        
    }

    private void HashCore()
    {
        Blake3Context context = default;
        using DeterministicSpan<Blake3Context> _ = DeterministicSpan.ProtectSingle(&context);
        Blake3Context.Initialize(&context);
    }
}
