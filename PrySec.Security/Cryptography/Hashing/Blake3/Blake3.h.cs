using PrySec.Core.NativeTypes;
using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Hashing.Blake3;

public unsafe partial class Blake3
{
    public const string BLAKE3_VERSION = "1.3.1";

    /// <summary>
    /// in bytes
    /// </summary>
    private const int BLAKE3_KEY_LEN = 32;

    private const int BLAKE3_KEY_DWORD_LEN = 8;
    
    // Outputs shorter than the default length of 32 bytes (256 bits) provide less security.
    // An N-bit BLAKE3 output is intended to provide N bits of first and second preimage resistance
    // and N/2 bits of collision resistance, for any N up to 256.
    // Longer outputs don't provide any additional security.
    /// <summary>
    /// in bytes
    /// </summary>
    private const int BLAKE3_OUT_LEN = 32;
    private const uint BLAKE3_BLOCK_LEN = 64u;
    private const uint BLAKE3_CHUNK_LEN = 1024u;
    private const int BLAKE3_MAX_DEPTH = 54;
    private static int MAX_SIMD_DEGREE { get; }
    private static int MAX_SIMD_DEGREE_OR_2 { get; }
    private static uint BLAKE3_SIMD_DEGREE { get; }

    private enum Blake3Flags : byte
    {
        CHUNK_START = 1 << 0,
        CHUNK_END = 1 << 1,
        PARENT = 1 << 2,
        ROOT = 1 << 3,
        KEYED_HASH = 1 << 4,
        DERIVE_KEY_CONTEXT = 1 << 5,
        DERIVE_KEY_MATERIAL = 1 << 6,
    }

    private static readonly uint[] IV = new uint[]
    {
        0x6A09E667u, 0xBB67AE85u, 0x3C6EF372u, 0xA54FF53Au,
        0x510E527Fu, 0x9B05688Cu, 0x1F83D9ABu, 0x5BE0CD19u
    };

    private static readonly byte[,] MSG_SCHEDULE = new byte[7,16]
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
        {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
        {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
        {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
        {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
        {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
    };

    private static delegate*<uint*, byte*, uint, ulong, Blake3Flags, void> _compressInPlaceImpl;
    private static delegate*<byte**, ulong, uint, uint*, ulong, bool, Blake3Flags, Blake3Flags, Blake3Flags, byte*, void> _hashManyImpl;
    private static delegate*<uint*, byte*, uint, ulong, Blake3Flags, byte*, void> _compressXofImpl;

    static Blake3()
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
            // Uncomment once we have support for AVX512 in the .net runtime
            //_ when Avx512.IsSupported => 16,                                                  // 16
            _ when Avx2.IsSupported => UseSimdImplementation<Blake3HwIntrinsicsAvx2>(),         // 8
            _ when Sse41.IsSupported => UseSimdImplementation<Blake3HwIntrinsicsSse41>(),       // 4
            // TODO:
            //_ when Sse2.IsSupported => UseSimdImplementation<Blake3HwIntrinsicsSse2>(),       // 4
            //_ when AdvSimd.IsSupported => UseSimdImplementation<Blake3HwIntrinsicsAdvSimd>(), // 4
            _ => UseSimdImplementation<Blake3HwIntrinsicsDefault>()                             // 1
        };
    }

    private static uint UseSimdImplementation<T>() where T : IBlake3Implementation
    {
        _compressInPlaceImpl = &T.CompressInPlace;
        _hashManyImpl = &T.HashMany;
        _compressXofImpl = &T.CompressXof;
        return T.SimdDegree;
    }
}
