using PrySec.Core.NativeTypes;
using PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation.HwIntrinsics;
using PrySec.Security.MemoryProtection.Portable.XofOtp.Intrinsics.Hw;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.MemoryProtection.Portable.XofOtp.Intrinsics;

internal static unsafe class AlignedXorService__EffectiveArch
{
    /// <summary>
    /// <c>void Xor2dAligned(void* alignedKey, void* alignedTarget, Size_T length);</c>
    /// </summary>
    public static delegate*<void*, void*, Size_T, void> Xor2dAligned;

    /// <summary>
    /// <c>void Xor3dPartiallyAligned(void* alignedKeyKey, void* alignedKey, void* unalignedTarget, Size_T length);</c>
    /// </summary>
    public static delegate*<void*, void*, void*, Size_T, void> Xor3dPartiallyAligned;

    static AlignedXorService__EffectiveArch() => _ = 0 switch
    {
        _ when Avx2.IsSupported => Use<AlignedXorHwIntrinsicsAvx2>(),
        _ when Sse2.IsSupported => Use<AlignedXorHwIntrinsicsSse2>(),
        _ when AdvSimd.IsSupported => Use<AlignedXorHwIntrinsicsNeon>(),
        _ => Use<AlignedXorHwIntrinsicsDefault>()
    };

    private static int Use<T>() where T : IAlignedXorImplementation
    {
        Xor2dAligned = &T.Xor2dAligned;
        Xor3dPartiallyAligned = &T.Xor3dPartiallyAligned;
        return 0;
    }
}
