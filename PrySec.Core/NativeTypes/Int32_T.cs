using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Core.NativeTypes;

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