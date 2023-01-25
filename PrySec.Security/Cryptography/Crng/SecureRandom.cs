using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace PrySec.Security.Cryptography.Crng;

public static unsafe class SecureRandom
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Fill(void* ptr, Size_T byteSize) => RandomNumberGenerator.Fill(new Span<byte>(ptr, byteSize));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Fill(Span<byte> buffer) => RandomNumberGenerator.Fill(buffer);
}
