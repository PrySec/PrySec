using System.Runtime.InteropServices;

namespace PrySec.Core.NativeTypes;

[StructLayout(LayoutKind.Explicit, Size = sizeof(ulong))]
public readonly struct Size64_T
{
    [FieldOffset(0x0)]
    private readonly ulong value;

    private Size64_T(ulong value) => this.value = value;

    public static implicit operator ulong(Size64_T size) => size.value;

    public static implicit operator long(Size64_T size) => (long)size.value;

    public static implicit operator Size64_T(long i) => new((ulong)i);

    public static implicit operator Size64_T(ulong i) => new(i);

    public static explicit operator Size_T(Size64_T size) => (nuint)size.value;
    
    public static explicit operator Size64_T(Size_T size) => (ulong)size;
}