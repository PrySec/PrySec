using PrySec.Core;
using PrySec.Core.NativeTypes;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation.HwIntrinsics;

internal unsafe class Blake3XofOtpFinalizerHwIntrinsicsAvx2 : IBlake3XofOtpBlockFinalizerImplementation
{
    private const int VECTOR_SIZE = 32;

    public static void FinalizeBlock(void* destination, void* source, Size_T length)
    {
        byte* dst = (byte*)destination;
        byte* src = (byte*)source;
        for (; length >= VECTOR_SIZE; length -= VECTOR_SIZE, src += VECTOR_SIZE, dst += VECTOR_SIZE)
        {
            Avx.Store(dst, Avx2.Xor(Avx.LoadVector256(src), Avx.LoadVector256(dst)));
        }
        if (length > 0)
        {
            Blake3XofOtpFinalizerHwIntrinsicsSse2.FinalizeBlock(dst, src, length);
        }
    }
}
