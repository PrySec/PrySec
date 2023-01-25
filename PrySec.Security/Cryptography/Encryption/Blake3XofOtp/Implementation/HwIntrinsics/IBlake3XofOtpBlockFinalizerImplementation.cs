using PrySec.Core.NativeTypes;

namespace PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation.HwIntrinsics;

internal unsafe interface IBlake3XofOtpBlockFinalizerImplementation
{
    public static abstract void FinalizeBlock(void* destination, void* source, Size_T length);
}
