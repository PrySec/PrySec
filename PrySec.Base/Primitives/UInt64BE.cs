using PrySec.Base.Primitives.Converters;
using System;
using System.Runtime.InteropServices;

namespace PrySec.Base.Primitives
{
    [StructLayout(LayoutKind.Explicit, Size = sizeof(ulong))]
    public readonly struct UInt64BE
    {
        [FieldOffset(0x0)]
        private readonly ulong value;

        public UInt64BE(ulong value) =>
            this.value = BitConverter.IsLittleEndian
                ? EndiannessConverter.Swap(value)
                : value;

        public static explicit operator UInt64BE(ulong value) => new(value);

        public static implicit operator ulong(UInt64BE be) => be.value;
    }
}
