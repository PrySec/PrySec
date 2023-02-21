using PrySec.Core.NativeTypes;

namespace PrySec.Security.MemoryProtection.Portable.XofOtp.Intrinsics.Hw;

internal unsafe class AlignedXorHwIntrinsicsDefault : IAlignedXorImplementation
{
    public static void Xor2dAligned(void* alignedKey, void* alignedTarget, Size_T length)
    {
        ulong* src8 = (ulong*)alignedKey;
        ulong* dst8 = (ulong*)alignedTarget;
        for (; length >= sizeof(ulong); length -= sizeof(ulong), src8++, dst8++)
        {
            *dst8 ^= *src8;
        }
        uint* src4 = (uint*)src8;
        uint* dst4 = (uint*)dst8;
        if (length >= sizeof(uint))
        {
            length -= sizeof(uint);
            *dst4 ^= *src4;
        }
        ushort* src2 = (ushort*)src4;
        ushort* dst2 = (ushort*)dst4;
        if (length >= sizeof(ushort))
        {
            length -= sizeof(ushort);
            *dst2 ^= *src2;
        }
        if (length > 0)
        {
            *(byte*)dst2 ^= *(byte*)src2;
        }
    }

    public static void Xor3dPartiallyAligned(void* alignedKeyKey, void* alignedKey, void* unalignedTarget, Size_T length)
    {
        ulong* key8 = (ulong*)alignedKeyKey;
        ulong* src8 = (ulong*)alignedKey;
        ulong* dst8 = (ulong*)unalignedTarget;
        for (; length >= sizeof(ulong); length -= sizeof(ulong), src8++, dst8++, key8++)
        {
            *dst8 ^= *src8 ^ *key8;
        }
        uint* key4 = (uint*)key8;
        uint* src4 = (uint*)src8;
        uint* dst4 = (uint*)dst8;
        if (length >= sizeof(uint))
        {
            length -= sizeof(uint);
            *dst4 ^= *src4 ^ *key4;
        }
        ushort* key2 = (ushort*)key4;
        ushort* src2 = (ushort*)src4;
        ushort* dst2 = (ushort*)dst4;
        if (length >= sizeof(ushort))
        {
            length -= sizeof(ushort);
            *dst2 ^= (ushort)(*src2 ^ *key2);
        }
        if (length > 0)
        {
            *(byte*)dst2 ^= (byte)(*(byte*)src2 ^ *(byte*)key2);
        }
    }
}
