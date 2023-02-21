using PrySec.Core.NativeTypes;
using PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation.HwIntrinsics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.MemoryProtection.Portable.XofOtp.Intrinsics.Hw;

internal unsafe class AlignedXorHwIntrinsicsSse2 : IAlignedXorImplementation
{
    private const int VECTOR_SIZE = 16;

    public static void Xor2dAligned(void* alignedKey, void* alignedTarget, Size_T length)
    {
        byte* src = (byte*)alignedKey;
        byte* dst = (byte*)alignedTarget;
        for (; length >= VECTOR_SIZE; length -= VECTOR_SIZE, src += VECTOR_SIZE, dst += VECTOR_SIZE)
        {
            Vector128<byte> srcVec = Sse2.LoadAlignedVector128(src);
            Vector128<byte> dstVec = Sse2.LoadAlignedVector128(dst);
            Vector128<byte> result = Sse2.Xor(srcVec, dstVec);
            Sse2.StoreAlignedNonTemporal(dst, result);
        }
        if (length > 0)
        {
            AlignedXorHwIntrinsicsDefault.Xor2dAligned(src, dst, length);
        }
    }

    public static void Xor3dPartiallyAligned(void* alignedKeyKey, void* alignedKey, void* unalignedTarget, Size_T length)
    {
        byte* key = (byte*)alignedKeyKey;
        byte* src = (byte*)alignedKey;
        byte* dst = (byte*)unalignedTarget;
        for (; length >= VECTOR_SIZE; length -= VECTOR_SIZE, src += VECTOR_SIZE, dst += VECTOR_SIZE)
        {
            Vector128<byte> keyVec = Sse2.LoadAlignedVector128(src);
            Vector128<byte> srcVec = Sse2.LoadAlignedVector128(src);
            Vector128<byte> dstVec = Sse2.LoadVector128(dst);
            Vector128<byte> result = Sse2.Xor(Sse2.Xor(srcVec, keyVec), dstVec);
            Sse2.Store(dst, result);
        }
        if (length > 0)
        {
            AlignedXorHwIntrinsicsDefault.Xor3dPartiallyAligned(key, src, dst, length);
        }
    }
}
