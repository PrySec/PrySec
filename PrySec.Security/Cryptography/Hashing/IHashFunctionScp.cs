using PrySec.Base.Memory;

namespace PrySec.Security.Cryptography.Hashing
{
    public interface IHashFunctionScp
    {
        IUnmanaged<byte> ComputeHash<T>(ref IUnmanaged<T> input) where T : unmanaged;
    }
}