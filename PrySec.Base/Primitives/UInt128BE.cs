using PrySec.Base.Primitives.Converters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Base.Primitives
{
    [StructLayout(LayoutKind.Explicit, Size = 2 * sizeof(ulong))]
    public unsafe struct UInt128BE
    {
        [FieldOffset(0x0)]
        public ulong Hi;

        [FieldOffset(sizeof(ulong))]
        public ulong Lo;

        public UInt128BE(ulong value)
        {
            Hi = 0;
            Lo = (UInt64BE)value;
        }

        public void SwapEndianness()
        {
            ulong temp = EndiannessConverter.Swap(Hi);
            Hi = EndiannessConverter.Swap(Lo);
            Lo = temp;
        }
    }
}
