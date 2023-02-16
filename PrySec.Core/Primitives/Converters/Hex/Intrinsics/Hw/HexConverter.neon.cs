﻿using PrySec.Core.NativeTypes;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal unsafe class HexConverterHwIntrinsicsNeon : HexConverter128BitBase, IHexConverterImplementation
{
    public static int InputBlockSize => 16;

    public static int OutputBlockSize => 8;

    private static readonly Vector64<byte> _selectLowNibbles;

    private static readonly Vector64<byte> _selectHighNibbles;

    static HexConverterHwIntrinsicsNeon()
    {
        byte* selectLowNibblesData = stackalloc byte[8]
        {
            0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f,
        };
        byte* selectHighNibblesData = stackalloc byte[8]
        {
            0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
        };
        _selectLowNibbles = AdvSimd.LoadVector64(selectLowNibblesData);
        _selectHighNibbles = AdvSimd.LoadVector64(selectHighNibblesData);
    }

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output)
    {
        Size_T i = inputSize;
        for (; i - InputBlockSize >= 0; i -= InputBlockSize, input += InputBlockSize, output += OutputBlockSize)
        {
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector128<uint> uint32Input = AdvSimd.LoadVector128((uint*)input);

            // map ASCII hex values to byte values 0 - 15 using
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector128<byte> stretchedNibbles = AdvSimd.Or(
                AdvSimd.Add(// (input & 0xF) + (input >> 6)
                    AdvSimd.And(uint32Input, _0x0fMask), // (input & 0xF)
                    AdvSimd.And(AdvSimd.ShiftRightLogical(uint32Input, 6), _0x03Mask)),// (input >> 6) (shift as uint and 0 upper 6 bits in every byte)
                AdvSimd.And( // ((input >> 3) & 0x8);
                    AdvSimd.And(AdvSimd.ShiftRightLogical(uint32Input, 3), _0x0fMask), // (input >> 3) (shift as uint and 0 upper nibbles)
                    _0x08Mask)) // 0x8
                .AsByte();

            // select all high nibbles into first and third 8 byte block
            Vector64<byte> high = AdvSimd.VectorTableLookup(stretchedNibbles, _selectHighNibbles);

            // select all low nibbles into first and third 8 byte block
            Vector64<byte> low = AdvSimd.VectorTableLookup(stretchedNibbles, _selectLowNibbles);

            // shift high nibbles left by 4
            Vector64<byte> shiftedHigh = AdvSimd.ShiftLeftLogical(high, 4);

            // combine high and low nibbles
            Vector64<byte> result = AdvSimd.Or(shiftedHigh, low);

            // write result vector
            // AA BB CC DD EE FF GG HH
            AdvSimd.Store(output, result);
        }
        if (i > 0)
        {
            HexConverterHwIntrinsicsDefault.Unhexlify(input, i, output);
        }
    }
}
