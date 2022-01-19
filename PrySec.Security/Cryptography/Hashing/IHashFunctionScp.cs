using PrySec.Core.Memory;

namespace PrySec.Security.Cryptography.Hashing;

public interface IHashFunctionScp
{
    IUnmanaged<byte> ComputeHash<TData>(ref IUnmanaged<TData> input) where TData : unmanaged;

    TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input)
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
        where TData : unmanaged;
}
