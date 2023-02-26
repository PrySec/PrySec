﻿using PrySec.Core.NativeTypes;
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
            Sse2.Store(dst, Sse2.Xor(Sse2.LoadVector128(src), Sse2.LoadVector128(dst)));
        }
        if (length > 0)
        {
            Blake3XofOtpFinalizerHwIntrinsicsDefault.FinalizeBlock(dst, src, length);
        }
    }
}
