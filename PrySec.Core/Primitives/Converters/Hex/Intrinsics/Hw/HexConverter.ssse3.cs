using PrySec.Core.NativeTypes;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal unsafe class HexConverterHwIntrinsicsSsse3 : HexConverter128BitBase, IHexConverterImplementation
{
    public static int SimdInputBlockSize => 16;

    public static int SimdOutputBlockSize => 8;

    private static readonly Vector128<byte> _selectLowNibbles;

    private static readonly Vector128<byte> _selectHighNibbles;

    static HexConverterHwIntrinsicsSsse3()
    {
        byte* selectLowNibblesData = stackalloc byte[16]
        {
            0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        };
        byte* selectHighNibblesData = stackalloc byte[16]
        {
            0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        };
        _selectLowNibbles = Sse2.LoadVector128(selectLowNibblesData);
        _selectHighNibbles = Sse2.LoadVector128(selectHighNibblesData);
    }

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output)
    {
        for (; inputSize >= SimdInputBlockSize; inputSize -= SimdInputBlockSize, input += SimdInputBlockSize, output += SimdOutputBlockSize)
        {
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector128<uint> uint32Input = Sse2.LoadVector128((uint*)input);

            // map ASCII hex values to byte values 0 - 15 using
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            // result looks like this
            // 0H 0L 0H 0L 0H 0L 0H 0L (H = high nibble, L = lower nibble)
            Vector128<byte> stretchedNibbles = Sse2.Or(
                Sse2.Add(// (input & 0xF) + (input >> 6)
                    Sse2.And(uint32Input, _0x0fMask), // (input & 0xF)
                    // (input >> 6) (shift as uint and 0 upper 6 bits in every byte)
                    Sse2.And(Sse2.ShiftRightLogical(uint32Input, 6), _0x03Mask)),
                Sse2.And( // ((input >> 3) & 0x8);
                    // don't need to mask off "invalid" bits from shifting here!
                    // they get eliminated by 0x08 mask :)
                    Sse2.ShiftRightLogical(uint32Input, 3), // (input >> 3)
                    _0x08Mask)) // 0x8
                .AsByte();

            // select all high nibbles into first and third 8 byte block
            // 0.5 CPI (ILP)
            Vector128<byte> high = Ssse3.Shuffle(stretchedNibbles, _selectHighNibbles);

            // select all low nibbles into first and third 8 byte block
            // 0.5 CPI (ILP)
            Vector128<byte> low = Ssse3.Shuffle(stretchedNibbles, _selectLowNibbles);

            // shift high nibbles left by 4
            Vector128<byte> shiftedHigh = Sse2.ShiftLeftLogical(high.AsUInt64(), 4).AsByte();

            // combine high and low nibbles
            Vector128<byte> result = Sse2.Or(shiftedHigh, low);

            // write first 8 bytes of 00 00 00 00 00 00 00 00
            // AA BB CC DD EE FF GG HH
            *(ulong*)output = Vector128.GetLower(result).AsUInt64().ToScalar();
        }
        if (inputSize > 0)
        {
            HexConverterHwIntrinsicsDefault__EffectiveArch.Unhexlify(input, inputSize, output);
        }
    }
}
