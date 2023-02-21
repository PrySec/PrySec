using PrySec.Core;
using PrySec.Core.NativeTypes;
using PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation.HwIntrinsics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.MemoryProtection.Portable.XofOtp.Intrinsics.Hw;

internal unsafe class AlignedXorHwIntrinsicsAvx2 : IAlignedXorImplementation
{
    private const int VECTOR_SIZE = 32;

    public static void Xor2dAligned(void* alignedKey, void* alignedTarget, Size_T length)
    {
        byte* src = (byte*)alignedKey;
        byte* dst = (byte*)alignedTarget;
        for (; length >= VECTOR_SIZE; length -= VECTOR_SIZE, src += VECTOR_SIZE, dst += VECTOR_SIZE)
        {
            Vector256<byte> srcVec = Avx.LoadAlignedVector256(src);
            Vector256<byte> dstVec = Avx.LoadAlignedVector256(dst);
            Vector256<byte> result = Avx2.Xor(srcVec, dstVec);
            Avx.StoreAligned(dst, result);
        }
        if (length > 0)
        {
            AlignedXorHwIntrinsicsSse2.Xor2dAligned(src, dst, length);
        }
    }

    public static void Xor3dPartiallyAligned(void* alignedKeyKey, void* alignedKey, void* unalignedTarget, Size_T length)
    {
        byte* key = (byte*)alignedKeyKey;
        byte* src = (byte*)alignedKey;
        byte* dst = (byte*)unalignedTarget;
        for (; length >= VECTOR_SIZE; length -= VECTOR_SIZE, src += VECTOR_SIZE, dst += VECTOR_SIZE)
        {
            Vector256<byte> keyVec = Avx.LoadAlignedVector256(key);
            Vector256<byte> srcVec = Avx.LoadAlignedVector256(src);
            Vector256<byte> dstVec = Avx.LoadVector256(dst);
            Vector256<byte> result = Avx2.Xor(Avx2.Xor(srcVec, keyVec), dstVec);
            Avx.Store(dst, result);
        }
        if (length > 0)
        {
            AlignedXorHwIntrinsicsSse2.Xor3dPartiallyAligned(key, src, dst, length);
        }
    }
}
