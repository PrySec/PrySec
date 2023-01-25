using PrySec.Core.Memory;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Blake2;

public unsafe partial class Blake2bScp : IHashFunctionScp
{
    private void Initialize<TInputMemory>(ref Blake2State<TInputMemory> state) where TInputMemory : IUnmanaged
    {
        // Initialize State vector h with IV
        fixed (ulong* pInitialHash = IV)
        {
            Unsafe.CopyBlockUnaligned(state.Hash, pInitialHash, IV_BYTE_SIZE);
        }

        // Mix key size (cbKeyLen) and desired hash length (cbHashLen) into h0
        *state.Hash ^= 0x01010000u | (state.KeyLength << 8) | state.DigestLength;
    }

    private TOutputMemory HashCore<TInputMemory, TOutputMemory>(ref Blake2State<TInputMemory> state)
        where TInputMemory : IUnmanaged
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        TOutputMemory result;
        fixed (ulong* pIv = IV)
        {
            using (IMemoryAccess<byte> access = state.Input.GetAccess<byte>())
            {
                BlakeCompressionState compressionState = new(state.Hash, access.Pointer, pIv, access.ByteSize);
                HashCoreImpl(&compressionState);
            }
            result = TOutputMemory.Allocate(state.DigestLength);
            using IMemoryAccess<byte> resultAccess = result.GetAccess();
            Unsafe.CopyBlockUnaligned(resultAccess.Pointer, state.Hash, resultAccess.ByteSize);
        }

        // return first cbHashLen bytes of little endian state vector h
        return result;
    }
}