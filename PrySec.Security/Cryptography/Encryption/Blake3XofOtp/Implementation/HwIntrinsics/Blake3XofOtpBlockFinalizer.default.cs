using PrySec.Core.NativeTypes;

namespace PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation.HwIntrinsics;

internal unsafe class Blake3XofOtpFinalizerHwIntrinsicsDefault : IBlake3XofOtpBlockFinalizerImplementation
{
    public static void FinalizeBlock(void* destination, void* source, Size_T length)
    {
        ulong* src8 = (ulong*)source;
        ulong* dst8 = (ulong*)destination;
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
}
