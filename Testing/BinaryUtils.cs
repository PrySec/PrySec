using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Testing;

internal static class BinaryUtils
{
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
}

[StructLayout(LayoutKind.Explicit, Size = sizeof(uint))]
public readonly struct Size32_T
{
    [FieldOffset(0x0)]
    private readonly uint value;

    private Size32_T(uint value) => this.value = value;

    public static implicit operator uint(Size32_T size) => size.value;

    public static implicit operator int(Size32_T size) => (int)size.value;

    public static implicit operator Size32_T(int i) => new((uint)i);

    public static implicit operator Size32_T(uint i) => new(i);
}

[StructLayout(LayoutKind.Explicit, Size = sizeof(uint))]
public readonly unsafe struct Int32_T
{
    [FieldOffset(0x0)]
    private readonly int _value;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public Int32_T(int value) => _value = value;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static explicit operator Int32_T(bool b) => new(*(byte*)&b);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static implicit operator int(Int32_T u) => u._value;
}
