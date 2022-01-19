using PrySec.Core.NativeTypes;
using System;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace PrySec.Core.Primitives;

public static unsafe class BinaryUtils
{
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
}