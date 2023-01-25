using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Portable;

namespace PrySec.Security.Cryptography.Hashing;

/// <summary>
/// A Secure Cryptography Provider representing a hash function.
/// </summary>
public interface IHashFunctionScp
{
    DeterministicMemory<byte> ComputeHash(IUnmanaged input);

    DeterministicMemory<byte> ComputeHash<TInputMemory>(ref TInputMemory input) where TInputMemory : IUnmanaged;

    TOutputMemory ComputeHash<TOutputMemory>(IUnmanaged input)
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;

    TOutputMemory ComputeHash<TInputMemory, TOutputMemory>(ref TInputMemory input)
        where TInputMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;
}

/// <summary>
/// A Secure Cryptography Provider representing a hash function with variable output length.
/// </summary>
public interface IVariableLengthHashFunctionScp : IHashFunctionScp
{
    DeterministicMemory<byte> ComputeHash(IUnmanaged input, Size_T outputLength);

    DeterministicMemory<byte> ComputeHash<TInputMemory>(ref TInputMemory input, Size_T outputLength) where TInputMemory : IUnmanaged;

    TOutputMemory ComputeHash<TOutputMemory>(IUnmanaged input, Size_T outputLength)
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;

    TOutputMemory ComputeHash<TInputMemory, TOutputMemory>(ref TInputMemory input, Size_T outputLength)
        where TInputMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;
}

/// <summary>
/// A Secure Cryptography Provider representing a hash function with support for keyed hashing.
/// </summary>
public interface IKeyedHashFunctionScp : IHashFunctionScp
{
    DeterministicMemory<byte> ComputeHashKeyed(IUnmanaged input, IUnmanaged key);

    DeterministicMemory<byte> ComputeHashKeyed<TMemory>(ref TMemory input, ref TMemory key) where TMemory : IUnmanaged;

    TOutputMemory ComputeHashKeyed<TOutputMemory>(IUnmanaged input, IUnmanaged key) where TOutputMemory : IUnmanaged<TOutputMemory, byte>;

    TOutputMemory ComputeHashKeyed<TMemory, TOutputMemory>(ref TMemory input, ref TMemory key)
        where TMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;

    TOutputMemory ComputeHashKeyed<TInputMemory, TKeyMemory, TOutputMemory>(ref TInputMemory input, ref TKeyMemory key)
        where TInputMemory : IUnmanaged
        where TKeyMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;
}

/// <summary>
/// A Secure Cryptography Provider representing a hash function with variable output length and support for keyed hashing.
/// </summary>
public interface IVariableLengthKeyedHashFunctionScp : IVariableLengthHashFunctionScp, IKeyedHashFunctionScp
{
    DeterministicMemory<byte> ComputeHashKeyed(IUnmanaged input, IUnmanaged key, Size_T outputLength);

    DeterministicMemory<byte> ComputeHashKeyed<TMemory>(ref TMemory input, ref TMemory key, Size_T outputLength) where TMemory : IUnmanaged;

    TOutputMemory ComputeHashKeyed<TOutputMemory>(IUnmanaged input, IUnmanaged key, Size_T outputLength) where TOutputMemory : IUnmanaged<TOutputMemory, byte>;

    TOutputMemory ComputeHashKeyed<TMemory, TOutputMemory>(ref TMemory input, ref TMemory key, Size_T outputLength)
        where TMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;

    TOutputMemory ComputeHashKeyed<TInputMemory, TKeyMemory, TOutputMemory>(ref TInputMemory input, ref TKeyMemory key, Size_T outputLength)
        where TInputMemory : IUnmanaged
        where TKeyMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;
}

public interface IKeyDerivationFunctionScp
{
    DeterministicMemory<byte> DeriveKey(IUnmanaged key, Size_T derivedKeyLength);

    DeterministicMemory<byte> DeriveKey<TKeyMemory>(ref TKeyMemory key, Size_T derivedKeyLength) where TKeyMemory : IUnmanaged;

    TOutputMemory DeriveKey<TOutputMemory>(IUnmanaged key, Size_T derivedKeyLength) where TOutputMemory : IUnmanaged<TOutputMemory, byte>;

    TOutputMemory DeriveKey<TKeyMemory, TOutputMemory>(ref TKeyMemory input, Size_T derivedKeyLength)
        where TKeyMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;
}