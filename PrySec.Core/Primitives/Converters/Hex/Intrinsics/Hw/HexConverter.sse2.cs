using PrySec.Core.NativeTypes;
using System;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using PrySec.Core.HwPrimitives;
using System.Diagnostics;
using System.Runtime.Intrinsics.Arm;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal unsafe class HexConverterHwIntrinsicsSse2 : HexConverter128BitBase, IHexConverterImplementation
{
    public static int InputBlockSize => 16;

    public static int OutputBlockSize => 8;

    private static readonly Vector128<byte> _clean11Mask;

    private static readonly Vector128<byte> _clean22Mask;

    private static readonly Vector128<byte> _clean44Mask;

    private static readonly Vector128<byte> _clean88Mask;

    static HexConverterHwIntrinsicsSse2()
    {
        byte* clean44MaskData = stackalloc byte[16]
        {
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff,
            0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff,
        };
        byte* clean88MaskData = stackalloc byte[16]
        {
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff
        };
        _clean11Mask = Vector128.Create(0xFF00FF00u).AsByte();
        _clean22Mask = Vector128.Create(0xFF0000FFu).AsByte();
        _clean44Mask = Sse2.LoadVector128(clean44MaskData);
        _clean88Mask = Sse2.LoadVector128(clean88MaskData);
    }

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output)
    {
        for (; inputSize - InputBlockSize >= 0; inputSize -= InputBlockSize, input += InputBlockSize, output += OutputBlockSize)
        {
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector128<uint> uint32Input = Sse2.LoadVector128((uint*)input);

            // map ASCII hex values to byte values 0 - 15 using
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector128<uint> stretchedNibbles = Sse2.Or(
                Sse2.Add(// (input & 0xF) + (input >> 6)
                    Sse2.And(uint32Input, _0x0fMask), // (input & 0xF)
                    // (input >> 6) (shift as uint and 0 upper 6 bits in every byte)
                    Sse2.And(Sse2.ShiftRightLogical(uint32Input, 6), _0x03Mask)),
                Sse2.And( // ((input >> 3) & 0x8);
                    // don't need to mask off "invalid" bits from shifting here!
                    // they get eliminated by 0x08 mask :)
                    Sse2.ShiftRightLogical(uint32Input, 3), // (input >> 3)
                    _0x08Mask)); // 0x8

            // result looks like this
            // 0H 0L 0H 0L 0H 0L 0H 0L (H = high nibble, L = lower nibble)
            // now shift high bytes left by 4 bit and interleave with lower nibble.
            Vector128<uint> highNibbles = Sse2.ShiftLeftLogical128BitLane(Sse2.ShiftLeftLogical(stretchedNibbles, 4), 1); // LITTLE ENDIAN!!!

            // highNibbles looks like this
            // 00 H0 L0 H0 L0 H0 L0 H0 (H = high nibble, L = lower nibble)
            // now combine higher and lower nibbles into hex decoded bytes.
            // combinedNibbles looks like this
            // 0H HL LH HL LH HL LH HL where every second byte is valid.
            Vector128<byte> combinedNibbles = Sse2.Or(highNibbles, stretchedNibbles).AsByte();

            // 00 HL 00 HL 00 HL 00 HL
            Vector128<byte> oneOne = Sse2.And(combinedNibbles, _clean11Mask);

            // HL 00 HL 00 HL 00 HL 00
            Vector128<byte> oneOneShifted = Sse2.ShiftRightLogical128BitLane(oneOne, 1);

            // AA AA BB BB CC CC DD DD
            Vector128<byte> twoTwoDirty = Sse2.Or(oneOneShifted, oneOne);

            // AA 00 00 BB CC 00 00 DD
            Vector128<byte> twoTwo = Sse2.And(twoTwoDirty, _clean22Mask);

            // 00 BB CC 00 00 DD AA 00
            Vector128<byte> twoTwoShifted = Sse2.ShiftRightLogical128BitLane(twoTwo, 2);

            // AA BB CC BB CC DD AA DD
            Vector128<byte> fourFourDirty = Sse2.Or(twoTwo, twoTwoShifted);

            // AA BB CC 00 00 00 00 DD
            Vector128<byte> fourFour = Sse2.And(fourFourDirty, _clean44Mask);

            // 00 00 00 DD EE FF GG 00
            Vector128<byte> fourFourShifted = Sse2.ShiftRightLogical128BitLane(fourFour, 4);

            // AA BB CC DD EE FF GG DD
            Vector128<byte> eightEightDirty = Sse2.Or(fourFour, fourFourShifted);

            // AA BB CC DD EE FF GG 00 00 00 00 00 00 00 00 00 HH =
            Vector128<byte> eightEight = Sse2.And(eightEightDirty, _clean88Mask);

            // 00 00 00 00 00 00 00 HH 00 00 00 00 00 00 00 00 00
            Vector128<byte> eightEitghShifted = Sse2.ShiftRightLogical128BitLane(eightEight, 8);

            // AA BB CC DD EE FF GG HH 00 00 00 00 00 00 00 00 HH
            Vector128<byte> result = Sse2.Or(eightEight, eightEitghShifted);

            // AA BB CC DD EE FF GG HH
            *(ulong*)output = Vector128.GetLower(result).AsUInt64().ToScalar();
        }
        if (inputSize > 0)
        {
            HexConverterHwIntrinsicsDefault.Unhexlify(input, inputSize, output);
        }
    }
}
