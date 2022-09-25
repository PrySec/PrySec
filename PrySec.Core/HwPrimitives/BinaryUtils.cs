using PrySec.Core.NativeTypes;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Core.HwPrimitives;

public static unsafe partial class BinaryUtils
{
    // TODO: consider using properties for direct inlining?
    private static readonly delegate*<int*, uint, int> _bitScanReverseImpl;
    private static readonly delegate*<int*, ulong, int> _bitScanReverse64Impl;
    private static readonly delegate*<uint, int> _populationCountImpl;
    private static readonly delegate*<ulong, int> _populationCount64Impl;

    static BinaryUtils()
    {
        _bitScanReverseImpl = 0 switch
        {
            _ when Lzcnt.IsSupported => &BitManipulationIntrinsics_Abm.BitScanReverse,
            _ when ArmBase.IsSupported => &BitManipulationIntrinsics_Arm.BitScanReverse,
            _ => &BitManipulation_Defaults.BitScanReverse
        };
        _bitScanReverse64Impl = 0 switch
        {
            _ when Lzcnt.X64.IsSupported => &BitManipulationIntrinsics_AbmX64.BitScanReverse,
            _ when ArmBase.Arm64.IsSupported => &BitManipulationIntrinsics_Arm64.BitScanReverse,
            _ => &BitManipulation_Defaults.BitScanReverse64
        };
        _populationCountImpl = 0 switch
        {
            _ when Popcnt.IsSupported => &BitManipulationIntrinsics_Abm.PopulationCount,
            _ when AdvSimd.IsSupported => &BitManipulationIntrinsics_AdvSimd.PopulationCount,
            _ => &BitManipulation_Defaults.PopulationCount
        };
        _populationCount64Impl = 0 switch
        {
            _ when Popcnt.X64.IsSupported => &BitManipulationIntrinsics_AbmX64.PopulationCount,
            _ when AdvSimd.IsSupported => &BitManipulationIntrinsics_AdvSimd.PopulationCount64,
            _ => &BitManipulation_Defaults.PopulationCount64
        };
    }

    /// <summary>
    /// Search the mask data from most significant bit (MSB) to least significant bit (LSB) for a set bit (1).
    /// </summary>
    /// <param name="index">[out] Loaded with the bit position of the first set bit (1) found.</param>
    /// <param name="mask">[in] The 32-bit value to search.</param>
    /// <returns>Nonzero if <paramref name="index"/> was set, or 0 if no set bits were found.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int BitScanReverse(int* index, uint mask) => _bitScanReverseImpl(index, mask);

    /// <summary>
    /// Search the mask data from most significant bit (MSB) to least significant bit (LSB) for a set bit (1).
    /// </summary>
    /// <param name="index">[out] Loaded with the bit position of the first set bit (1) found.</param>
    /// <param name="mask">[in] The 64-bit value to search.</param>
    /// <returns>Nonzero if <paramref name="index"/> was set, or 0 if no set bits were found.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int BitScanReverse(int* index, ulong mask) => _bitScanReverse64Impl(index, mask);

    /// <summary>
    /// Counts the number of <c>1</c> bits (population count) in a 32-bit unsigned integer.
    /// </summary>
    /// <param name="value">[in] The 32-bit unsigned integer for which we want the population count.</param>
    /// <returns>The number of <c>1</c> bits in the <paramref name="value"/> parameter.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int PopulationCount(uint value) => _populationCountImpl(value);

    /// <summary>
    /// Counts the number of <c>1</c> bits (population count) in a 64-bit unsigned integer.
    /// </summary>
    /// <param name="value">[in] The 64-bit unsigned integer for which we want the population count.</param>
    /// <returns>The number of <c>1</c> bits in the <paramref name="value"/> parameter.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int PopulationCount(ulong value) => _populationCount64Impl(value);

    /// <summary>
    /// Finds the largest power of two less than or equal to <paramref name="value"/>.
    /// </summary>
    /// <remarks>As a special case, returns <c>1</c> when <paramref name="value"/> is <c>0</c>.</remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ulong RoundDownToPowerOf2(ulong value)
    {
        int index;
        BitScanReverse(&index, value | 0x1);
        return 1uL << index;
    }

    /// <summary>
    /// Finds the largest power of two less than or equal to <paramref name="value"/>.
    /// </summary>
    /// <remarks>As a special case, returns <c>1</c> when <paramref name="value"/> is <c>0</c>.</remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static uint RoundDownToPowerOf2(uint value)
    {
        int index;
        BitScanReverse(&index, value | 0x1);
        return 1u << index;
    }

    /// <summary>
    /// log2(value)
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveOptimization)]
    public static int Ld(Size32_T value)
    {
        int v = value;

        int r = (Int32_T)(v > 0xFFFF) << 4;
        v >>= r;
        int shift = (Int32_T)(v > 0xFF) << 3;
        v >>= shift;
        r |= shift;
        shift = (Int32_T)(v > 0xF) << 2;
        v >>= shift;
        r |= shift;
        shift = (Int32_T)(v > 0x3) << 1;
        v >>= shift;
        r |= shift;
        r |= v >> 1;
        return r;
    }

    /// <summary>
    /// Checks if <paramref name="value"/> is a power of 2.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static bool Ip2(Size32_T value)
    {
        uint v = value;
        return (v & v - 1) == 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static unsafe void WriteUInt32BigEndian(uint* target, uint value) =>
        *target = BitConverter.IsLittleEndian
            ? BinaryPrimitives.ReverseEndianness(value)
            : value;

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static unsafe void WriteUInt64BigEndian(ulong* target, ulong value) =>
        *target = BitConverter.IsLittleEndian
            ? BinaryPrimitives.ReverseEndianness(value)
            : value;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe short ReadInt16LittleEndian(short* ptr) =>
        BinaryPrimitives.ReadInt16LittleEndian(new Span<byte>(ptr, sizeof(short)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe int ReadInt32LittleEndian(int* ptr) =>
        BinaryPrimitives.ReadInt32LittleEndian(new Span<byte>(ptr, sizeof(int)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe long ReadInt64LittleEndian(long* ptr) =>
        BinaryPrimitives.ReadInt64LittleEndian(new Span<byte>(ptr, sizeof(long)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe ushort ReadUInt16LittleEndian(ushort* ptr) =>
        BinaryPrimitives.ReadUInt16LittleEndian(new Span<byte>(ptr, sizeof(ushort)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe uint ReadUInt32LittleEndian(uint* ptr) =>
        BinaryPrimitives.ReadUInt32LittleEndian(new Span<byte>(ptr, sizeof(uint)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe ulong ReadUInt64LittleEndian(ulong* ptr) =>
        BinaryPrimitives.ReadUInt64LittleEndian(new Span<byte>(ptr, sizeof(ulong)));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void WriteInt16LittleEndian(void* ptr, short value) =>
        BinaryPrimitives.WriteInt16LittleEndian(new Span<byte>(ptr, sizeof(short)), value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void WriteInt32LittleEndian(void* ptr, int value) =>
        BinaryPrimitives.WriteInt32LittleEndian(new Span<byte>(ptr, sizeof(int)), value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void WriteInt64LittleEndian(void* ptr, long value) =>
        BinaryPrimitives.WriteInt64LittleEndian(new Span<byte>(ptr, sizeof(long)), value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void WriteUInt16LittleEndian(void* ptr, ushort value) =>
        BinaryPrimitives.WriteUInt16LittleEndian(new Span<byte>(ptr, sizeof(ushort)), value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void WriteUInt32LittleEndian(void* ptr, uint value) =>
        BinaryPrimitives.WriteUInt32LittleEndian(new Span<byte>(ptr, sizeof(uint)), value);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void WriteUInt64LittleEndian(void* ptr, ulong value) =>
        BinaryPrimitives.WriteUInt64LittleEndian(new Span<byte>(ptr, sizeof(ulong)), value);
}