using PrySec.Core.NativeTypes;

namespace PrySec.Security.MemoryProtection.Portable.XofOtp.Intrinsics.Hw;

internal unsafe interface IAlignedXorImplementation
{
    public static abstract void Xor2dAligned(void* alignedKey, void* alignedTarget, Size_T length);

    public static abstract void Xor3dPartiallyAligned(void* alignedKeyKey, void* alignedKey, void* unalignedTarget, Size_T length);
}
