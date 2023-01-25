using PrySec.Core.NativeTypes;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation.HwIntrinsics;

internal unsafe class Blake3XofOtpFinalizerHwIntrinsicsSse2 : IBlake3XofOtpBlockFinalizerImplementation
{
    private const int VECTOR_SIZE = 16;

    public static void FinalizeBlock(void* destination, void* source, Size_T length)
    {
        byte* dst = (byte*)destination;
        byte* src = (byte*)source;
        for (; length >= VECTOR_SIZE; length -= VECTOR_SIZE, src += VECTOR_SIZE, dst += VECTOR_SIZE)
        {
            Vector128<byte> srcVec = Sse2.LoadVector128(src);
            Vector128<byte> dstVec = Sse2.LoadVector128(dst);
            Vector128<byte> result = Sse2.Xor(srcVec, dstVec);
            Sse2.Store(dst, result);
        }
        if (length > 0)
        {
            Blake3XofOtpFinalizerHwIntrinsicsDefault.FinalizeBlock(dst, src, length);
        }
    }
}
