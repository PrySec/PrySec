using PrySec.Base.Primitives.Converters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Base.Primitives
{
    [StructLayout(LayoutKind.Explicit, Size = sizeof(uint))]
    public readonly struct UInt32BE
    {
        [FieldOffset(0x0)]
        private readonly uint value;

        public UInt32BE(uint value) =>
            this.value = BitConverter.IsLittleEndian
                ? EndiannessConverter.Swap(value)
                : value;

        public static explicit operator UInt32BE(uint value) => new(value);

        public static implicit operator uint(UInt32BE be) => be.value;
    }
}
