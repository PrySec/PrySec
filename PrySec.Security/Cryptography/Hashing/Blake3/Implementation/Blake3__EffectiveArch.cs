using PrySec.Core.ArrayTypes;
using PrySec.Core.HwPrimitives;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Security.Cryptography.Hashing.Blake3.Implementation.HwIntrinsics;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Hashing.Blake3.Implementation;

public unsafe abstract partial class Blake3__EffectiveArch
{
    public static string Version => "1.3.1";

    /// <summary>
    /// in bytes
    /// </summary>
    internal const int BLAKE3_KEY_LEN = 32;

    internal const int BLAKE3_KEY_DWORD_LEN = 8;

    // Outputs shorter than the default length of 32 bytes (256 bits) provide less security.
    // An N-bit BLAKE3 output is intended to provide N bits of first and second preimage resistance
    // and N/2 bits of collision resistance, for any N up to 256.
    // Longer outputs don't provide any additional security.
    /// <summary>
    /// in bytes
    /// </summary>
    internal const int BLAKE3_OUT_LEN = 32;
    internal const uint BLAKE3_BLOCK_LEN = 64u;
    internal const uint BLAKE3_CHUNK_LEN = 1024u;
    internal const int BLAKE3_MAX_DEPTH = 54;

    internal static int MAX_SIMD_DEGREE { get; }
    internal static int MAX_SIMD_DEGREE_OR_2 { get; }
    internal static uint BLAKE3_SIMD_DEGREE { get; }

    // should be "const uint* const"
    internal static readonly uint* IV;
    internal const int IVLength = 8;
    internal const int IVByteSize = IVLength * sizeof(uint);

    // should be "const byte * const *"
    internal static readonly Array2d<byte> MSG_SCHEDULE;

    internal static delegate*<uint*, byte*, uint, ulong, Blake3Flags, void> CompressInPlaceImpl;
    internal static delegate*<byte**, ulong, uint, uint*, ulong, bool, Blake3Flags, Blake3Flags, Blake3Flags, byte*, void> HashManyImpl;
    internal static delegate*<uint*, byte*, uint, ulong, Blake3Flags, byte*, void> CompressXofImpl;

    static Blake3__EffectiveArch()
    {
        MAX_SIMD_DEGREE = RuntimeInformation.OSArchitecture switch
        {
            Architecture.X86 or Architecture.X64 => 8, // actually 16 for AVX-512
            Architecture.Arm64 => 4,
            _ => MAX_SIMD_DEGREE = 1,
        };

        MAX_SIMD_DEGREE_OR_2 = Math.Max(MAX_SIMD_DEGREE, 2);

        BLAKE3_SIMD_DEGREE = 0 switch
        {
            // Uncomment once we have support for AVX512 in the .NET runtime
            //_ when Avx512.IsSupported => 16,                                                  // 16
            _ when Avx2.IsSupported => UseSimdImplementation<Blake3HwIntrinsicsAvx2>(),         // 8
            _ when Sse41.IsSupported => UseSimdImplementation<Blake3HwIntrinsicsSse41>(),       // 4
            // TODO:
            //_ when Sse2.IsSupported => UseSimdImplementation<Blake3HwIntrinsicsSse2>(),       // 4
            //_ when AdvSimd.IsSupported => UseSimdImplementation<Blake3HwIntrinsicsAdvSimd>(), // 4
            _ => UseSimdImplementation<Blake3HwIntrinsicsDefault>()                             // 1
        };

        // initialize IV on the heap
        uint* ivData = stackalloc uint[]
        {
            0x6A09E667u,
            0xBB67AE85u,
            0x3C6EF372u,
            0xA54FF53Au,
            0x510E527Fu,
            0x9B05688Cu,
            0x1F83D9ABu,
            0x5BE0CD19u
        };
        // TODO: maybe do aligned allocation here!
        IV = (uint*)MemoryManager.Malloc(IVByteSize);
        MemoryManager.Memcpy(IV, ivData, IVByteSize);

        byte[,] messageScheduleData = new byte[7, 16]
        {
            {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
            {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
            {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
            {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
            {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
            {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
            {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
        };
        // TODO: maybe do aligned allocation here!
        byte* pMessageScheduleBuffer = (byte*)MemoryManager.Malloc(7 * 16);
        Array2d<byte> messageScheduleBuffer = new(pMessageScheduleBuffer, 7, 16);

        for (int row = 0; row < 7; row++)
        {
            for (int col = 0; col < 16; col++)
            {
                messageScheduleBuffer[row, col] = messageScheduleData[row, col];
            }
        }
        MSG_SCHEDULE = messageScheduleBuffer;
    }

    internal static uint UseSimdImplementation<T>() where T : IBlake3Implementation
    {
        CompressInPlaceImpl = &T.CompressInPlace;
        HashManyImpl = &T.HashMany;
        CompressXofImpl = &T.CompressXof;
        return T.SimdDegree;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void LoadKeyWords(byte* key, uint* keyWords)
    {
        uint* keyPtrAsUInt = (uint*)key;
        keyWords[0] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt);
        keyWords[1] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 1);
        keyWords[2] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 2);
        keyWords[3] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 3);
        keyWords[4] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 4);
        keyWords[5] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 5);
        keyWords[6] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 6);
        keyWords[7] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static void StoreCvWords(byte* bytesOut, uint* cvWords)
    {
        uint* bytesOutAsUInt = (uint*)bytesOut;
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt, cvWords[0]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 1, cvWords[1]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 2, cvWords[2]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 3, cvWords[3]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 4, cvWords[4]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 5, cvWords[5]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 6, cvWords[6]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 7, cvWords[7]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint CounterLow(ulong counter) => (uint)counter;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    internal static uint CounterHigh(ulong counter) => (uint)(counter >> 32);
}
