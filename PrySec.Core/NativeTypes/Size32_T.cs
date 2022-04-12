using System.Runtime.InteropServices;

namespace PrySec.Core.NativeTypes;

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