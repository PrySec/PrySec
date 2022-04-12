using PrySec.Core.Primitives.Converters;
using System;
using System.Runtime.InteropServices;

namespace PrySec.Core.NativeTypes;

[StructLayout(LayoutKind.Explicit, Size = sizeof(uint))]
public readonly struct UInt32BE_T
{
    [FieldOffset(0x0)]
    private readonly uint value;

    public UInt32BE_T(uint value) =>
        this.value = BitConverter.IsLittleEndian
            ? EndiannessConverter.Swap(value)
            : value;

    public static explicit operator UInt32BE_T(uint value) => new(value);

    public static implicit operator uint(UInt32BE_T be) => be.value;
}