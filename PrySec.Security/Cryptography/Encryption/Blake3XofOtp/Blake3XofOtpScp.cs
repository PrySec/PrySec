using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation;
using PrySec.Security.Cryptography.Hashing.Blake3;
using PrySec.Security.Cryptography.Hashing.Blake3.Implementation;
using PrySec.Security.MemoryProtection.Portable.Sentinels;

namespace PrySec.Security.Cryptography.Encryption.Blake3XofOtp;

public unsafe class Blake3XofOtpScp : Blake3__EffectiveArch
{
    private readonly string _context;

    public Blake3XofOtpScp(string keyDerivationContext) => _context = keyDerivationContext;

    public void ComputeInline<TKeyMemory>(ref TKeyMemory key, byte* target, Size_T targetByteSize)
        where TKeyMemory : IUnmanaged
    {
        Blake3Context blake3 = default;
        using DeterministicSentinel<Blake3Context> _ = DeterministicSentinel.Protect(&blake3);
        Blake3Scp.InternalInitializeDeriveKeyFromContext(&blake3, _context);
        // override finalizer function
        blake3.BlockFinalizerFunction = Blake3XofOtpBlockFinalizer__EffectiveArch.BlockFinalizerFunction;
        using (IMemoryAccess<byte> keyAccess = key.GetAccess<byte>())
        {
            Blake3Context.Update(&blake3, keyAccess.Pointer, keyAccess.ByteSize);
        }
        Blake3Context.Finalize(&blake3, target, targetByteSize);
    }
}
