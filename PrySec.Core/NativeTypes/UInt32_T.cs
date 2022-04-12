using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Core.NativeTypes;

[StructLayout(LayoutKind.Explicit, Size = sizeof(uint))]
public readonly unsafe struct UInt32_T
{
    [FieldOffset(0x0)]
    private readonly uint _value;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public UInt32_T(uint value) => _value = value;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static explicit operator UInt32_T(bool b) => new(*(byte*)&b);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static implicit operator uint(UInt32_T u) => u._value;
}