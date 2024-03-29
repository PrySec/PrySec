﻿using PrySec.Core.NativeTypes;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using PrySec.Core.HwPrimitives;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

using static AvxPrimitives;

internal unsafe class HexConverterHwIntrinsicsAvx2 : IHexConverterImplementation
{
    public static int SimdInputBlockSize => 32;

    public static int SimdOutputBlockSize => 16;

    private static readonly Vector256<byte> _selectLowNibbles;

    private static readonly Vector256<byte> _selectHighNibbles;

    private static readonly Vector256<uint> _0x03Mask;

    private static readonly Vector256<uint> _0x08Mask;

    private static readonly Vector256<uint> _0x0fMask;

    static HexConverterHwIntrinsicsAvx2()
    {
        byte* selectLowNibblesData = stackalloc byte[32]
        {
            0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x11, 0x13, 0x15, 0x17, 0x19, 0x1b, 0x1d, 0x1f,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        };

        byte* selectHighNibblesData = stackalloc byte[32]
        {
            0x00, 0x02, 0x04, 0x06, 0x08, 0x0a, 0x0c, 0x0e,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x10, 0x12, 0x14, 0x16, 0x18, 0x1a, 0x1c, 0x1e,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
        };
        _selectLowNibbles = Avx.LoadVector256(selectLowNibblesData);
        _selectHighNibbles = Avx.LoadVector256(selectHighNibblesData);
        _0x03Mask = Vector256.Create(0x03030303u);
        _0x08Mask = Vector256.Create(0x08080808u);
        _0x0fMask = Vector256.Create(0x0F0F0F0Fu);
    }

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output)
    {
        for ( ; inputSize >= SimdInputBlockSize; inputSize -= SimdInputBlockSize, input += SimdInputBlockSize, output += SimdOutputBlockSize)
        {
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector256<uint> uint32Input = Avx.LoadVector256((uint*)input);

            // map ASCII hex values to byte values 0 - 15 using
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            // result looks like this
            // 0H 0L 0H 0L 0H 0L 0H 0L (H = high nibble, L = lower nibble)
            Vector256<byte> stretchedNibbles = Avx2.Or(
                Avx2.Add(// (input & 0xF) + (input >> 6)
                    Avx2.And(uint32Input, _0x0fMask), // (input & 0xF)
                    // (input >> 6) (shift as uint and 0 upper 6 bits in every byte)
                    Avx2.And(Avx2.ShiftRightLogical(uint32Input, 6), _0x03Mask)),
                Avx2.And( // ((input >> 3) & 0x8);
                    // don't need to mask off "invalid" bits from shifting here!
                    // they get eliminated by 0x08 mask :)
                    Avx2.ShiftRightLogical(uint32Input, 3), // (input >> 3)
                    _0x08Mask))
                .AsByte(); // 0x8
            
            // select all high nibbles into first and third 8 byte block
            // 0.5 CPI (ILP)
            Vector256<byte> high = Avx2.Shuffle(stretchedNibbles, _selectHighNibbles);

            // select all low nibbles into first and third 8 byte block
            // 0.5 CPI (ILP)
            Vector256<byte> low = Avx2.Shuffle(stretchedNibbles, _selectLowNibbles);

            // shift high nibbles left by 4
            Vector256<byte> shiftedHigh = Avx2.ShiftLeftLogical(high.AsUInt64(), 4).AsByte();

            // combine high and low nibbles
            Vector256<byte> combined = Avx2.Or(shiftedHigh, low);

            // blend first and third 8 byte block into first 16 bytes
            Vector256<byte> result = Avx2.Permute4x64(combined.AsInt64(), _MM_SHUFFLE(3, 1, 2, 0)).AsByte();

            // store first 16 bytes of result
            Sse2.Store(output, result.GetLower());
        }
        if (inputSize > 0uL)
        {
            HexConverterHwIntrinsicsSsse3.Unhexlify(input, inputSize, output);
        }
    }
}
