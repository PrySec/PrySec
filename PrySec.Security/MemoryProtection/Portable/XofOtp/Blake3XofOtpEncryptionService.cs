using PrySec.Core;
using PrySec.Core.Memory;
using PrySec.Security.Cryptography.Crng;
using PrySec.Security.Cryptography.Encryption.Blake3XofOtp;
using PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Implementation;
using System;

namespace PrySec.Security.MemoryProtection.Portable.XofOtp;

internal static unsafe class Blake3XofOtpEncryptionService
{
    private static readonly Blake3XofOtpScp _otpService = new($"https://github.com/frederik-hoeft/PrySec 2023-01-25 22:10:07 PrySec BLAKE3 XOF OTP SCP");

    private static readonly IUnmanaged _keyMemory;

    static Blake3XofOtpEncryptionService()
    {
        // TODO: use protected memory + fluent/dynamic reference!
        // TODO: use constant for 64 (IV/key size)
        _keyMemory = UnmanagedMemory<byte>.Allocate(64);
        using IMemoryAccess<byte> access = _keyMemory.GetAccess<byte>();
        SecureRandom.Fill(access.Pointer, access.ByteSize);
    }

    public static void Protect<T>(Blake3XofOtpEncryptedMemory<T> memory) where T : unmanaged
    {
        if (memory.NativeHandle != IntPtr.Zero && memory.State is ProtectionState.Unprotected)
        {
            ApplyOtp(memory);
            memory.State = ProtectionState.Protected;
        }
    }

    public static void Unprotect<T>(Blake3XofOtpEncryptedMemory<T> memory) where T : unmanaged
    {
        if (memory.NativeHandle != IntPtr.Zero && memory.State is ProtectionState.Protected)
        {
            ApplyOtp(memory);
            memory.State = ProtectionState.Unprotected;
        }
    }

    private static void ApplyOtp<T>(Blake3XofOtpEncryptedMemory<T> memory) where T : unmanaged
    {
        // TODO: use actually protected memory + maybe use stack-based buffer?
        DeterministicMemory<byte> keyBuffer = DeterministicMemory<byte>.CreateFrom(new Span<byte>(memory.NativeHandle.ToPointer(), Blake3XofOtpEncryptedMemory<T>.IVSize));
        using (IMemoryAccess<byte> targetAccess = keyBuffer.GetAccess<byte>())
        using (IMemoryAccess<byte> sourceAccess = _keyMemory.GetAccess<byte>())
        {
            Blake3XofOtpBlockFinalizer__EffectiveArch.BlockFinalizerFunction(targetAccess.Pointer, sourceAccess.Pointer, targetAccess.ByteSize);
        }
        _otpService.ComputeInline(ref keyBuffer, (byte*)memory.BasePointer, memory.ByteSize);
        keyBuffer.Dispose();
    }
}
