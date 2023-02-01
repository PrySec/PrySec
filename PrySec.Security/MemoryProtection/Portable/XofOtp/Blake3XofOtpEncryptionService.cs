using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Security.Cryptography.Crng;
using PrySec.Security.Cryptography.Encryption.Blake3XofOtp;
using PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;
using PrySec.Security.MemoryProtection.Portable.ProtectedMemory;
using PrySec.Security.MemoryProtection.Portable.XofOtp.Intrinsics;
using System;
using System.Diagnostics;

namespace PrySec.Security.MemoryProtection.Portable.XofOtp;

internal static unsafe class Blake3XofOtpEncryptionService
{
    private static readonly Blake3XofOtpScp _otpService = new($"https://github.com/frederik-hoeft/PrySec 2023-01-25 22:10:07 PrySec BLAKE3 XOF OTP SCP");

    private static readonly ProtectedMemory<byte> _principalKeyMemory;

    public const int KEY_SIZE = 64;

    static Blake3XofOtpEncryptionService()
    {
        // TODO: fluent/dynamic reference!
        _principalKeyMemory = ProtectedMemory<byte>.Allocate(KEY_SIZE + KEY_SIZE);
        using IMemoryAccess<byte> access = _principalKeyMemory.GetAccess<byte>();
        SecureRandom.Fill(access.Pointer, access.ByteSize);
        AlignedXorService__EffectiveArch.Xor2dAligned(access.Pointer, access.Pointer + KEY_SIZE, KEY_SIZE);
        Debug.WriteLine($"_principalKeyMemory base: 0x{(nint)_principalKeyMemory.BasePointer:x16}");
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
        // TODO: use actually protected memory
        byte* pBlakeXofKey = stackalloc byte[KEY_SIZE];
        MemoryManager.Memcpy(pBlakeXofKey, memory.NativeHandle.ToPointer(), KEY_SIZE);
        using DeterministicMemory<byte> blakeXofKey = DeterministicMemory.ProtectOnly(pBlakeXofKey, KEY_SIZE);
        using (IMemoryAccess<byte> principalKeyAccess = _principalKeyMemory.GetAccess())
        {
            AlignedXorService__EffectiveArch.Xor3dPartiallyAligned(principalKeyAccess.Pointer, principalKeyAccess.Pointer + KEY_SIZE, pBlakeXofKey, KEY_SIZE);
        }
        _otpService.ComputeInline__Internal(pBlakeXofKey, KEY_SIZE, (byte*)memory.BasePointer, memory.ByteSize);
    }
}