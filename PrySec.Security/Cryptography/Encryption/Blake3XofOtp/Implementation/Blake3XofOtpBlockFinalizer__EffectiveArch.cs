using PrySec.Core.NativeTypes;
using PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation.HwIntrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation;

internal static unsafe class Blake3XofOtpBlockFinalizer__EffectiveArch
{
    public static delegate*<void*, void*, Size_T, void> BlockFinalizerFunction;

    static Blake3XofOtpBlockFinalizer__EffectiveArch()
    {
        BlockFinalizerFunction = 0 switch
        {
            _ when Avx2.IsSupported => Use<Blake3XofOtpFinalizerHwIntrinsicsAvx2>(),
            _ when Sse2.IsSupported => Use<Blake3XofOtpFinalizerHwIntrinsicsSse2>(),
            _ when AdvSimd.IsSupported => Use<Blake3XofOtpFinalizerHwIntrinsicsNeon>(),
            _ => Use<Blake3XofOtpFinalizerHwIntrinsicsDefault>()
        };
    }

    private static delegate*<void*, void*, Size_T, void> Use<T>() where T : IBlake3XofOtpBlockFinalizerImplementation =>
        &T.FinalizeBlock;
}