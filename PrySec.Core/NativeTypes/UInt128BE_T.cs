using PrySec.Core.Primitives.Converters;
using System.Numerics;
using System.Runtime.InteropServices;

namespace PrySec.Core.NativeTypes;

[StructLayout(LayoutKind.Explicit, Size = 2 * sizeof(ulong))]
public readonly unsafe struct UInt128BE_T
{
    [FieldOffset(0x0)]
    public readonly ulong Hi;

    [FieldOffset(sizeof(ulong))]
    public readonly ulong Lo;

    public UInt128BE_T(ulong value)
    {
        Hi = 0;
        Lo = (UInt64BE_T)value;
    }

    private UInt128BE_T(ulong hi, ulong lo)
    {
        Hi = hi; 
        Lo = lo;
    }

    public UInt128BE_T SwapEndianness()
    {
        ulong temp = EndiannessConverter.Swap(Hi);
        ulong hi = EndiannessConverter.Swap(Lo);
        ulong lo = temp;
        return new UInt128BE_T(hi, lo);
    }

    // TODO: ...
    //public static UInt128BE_T operator >>(UInt128BE_T uint128, int count)
    //{
    //    ulong lo = uint128.Lo >>> count;
    //    ulong hiToLow = uint128.Hi & ((1 << (count - 1)) - 1)
    //}
}