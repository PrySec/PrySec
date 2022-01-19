using PrySec.Core.Primitives.Converters;
using System.Runtime.InteropServices;

namespace PrySec.Core.NativeTypes;

[StructLayout(LayoutKind.Explicit, Size = 2 * sizeof(ulong))]
public unsafe struct UInt128BE_T
{
    [FieldOffset(0x0)]
    public ulong Hi;

    [FieldOffset(sizeof(ulong))]
    public ulong Lo;

    public UInt128BE_T(ulong value)
    {
        Hi = 0;
        Lo = (UInt64BE_T)value;
    }

    public void SwapEndianness()
    {
        ulong temp = EndiannessConverter.Swap(Hi);
        Hi = EndiannessConverter.Swap(Lo);
        Lo = temp;
    }
}