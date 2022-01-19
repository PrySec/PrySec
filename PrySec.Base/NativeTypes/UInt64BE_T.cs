using PrySec.Core.Primitives.Converters;
using System;
using System.Runtime.InteropServices;

namespace PrySec.Core.NativeTypes;

[StructLayout(LayoutKind.Explicit, Size = sizeof(ulong))]
public readonly struct UInt64BE_T
{
    [FieldOffset(0x0)]
    private readonly ulong value;

    public UInt64BE_T(ulong value) =>
        this.value = BitConverter.IsLittleEndian
            ? EndiannessConverter.Swap(value)
            : value;

    public static explicit operator UInt64BE_T(ulong value) => new(value);

    public static implicit operator ulong(UInt64BE_T be) => be.value;
}