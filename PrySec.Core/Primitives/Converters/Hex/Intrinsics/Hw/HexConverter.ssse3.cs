﻿using PrySec.Core.NativeTypes;
using System;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using PrySec.Core.HwPrimitives;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal unsafe class HexConverterHwIntrinsicsSsse3 : IHexConverterImplementation
{
    public static int InputBlockSize => 16;

    public static int OutputBlockSize => 8;

    private static readonly Vector128<byte> _shuffleData;

    private static readonly Vector128<uint> _0x03Mask;

    private static readonly Vector128<uint> _0x08Mask;

    private static readonly Vector128<uint> _0x0fMask;

    static HexConverterHwIntrinsicsSsse3()
    {
        byte* pShuffleData = stackalloc byte[16]
        {
            0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        };
        _shuffleData = Sse2.LoadVector128(pShuffleData);
        _0x03Mask = Vector128.Create(0x03030303u);
        _0x08Mask = Vector128.Create(0x08080808u);
        _0x0fMask = Vector128.Create(0x0F0F0F0Fu);
    }

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output, byte* workspaceBuffer)
    {
        Size_T i = inputSize;
        for (; i - InputBlockSize >= 0; i -= InputBlockSize, input += InputBlockSize, output += OutputBlockSize)
        {
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector128<uint> uint32Input = Sse2.LoadVector128((uint*)input);

            // map ASCII hex values to byte values 0 - 15 using
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector128<uint> stretchedNibbles = Sse2.Or(
                Sse2.Add(// (input & 0xF) + (input >> 6)
                    Sse2.And(uint32Input, _0x0fMask), // (input & 0xF)
                    Sse2.And(Sse2.ShiftRightLogical(uint32Input, 6), _0x03Mask)),// (input >> 6) (shift as uint and 0 upper 6 bits in every byte)
                Sse2.And( // ((input >> 3) & 0x8);
                    Sse2.And(Sse2.ShiftRightLogical(uint32Input, 3), _0x0fMask), // (input >> 3) (shift as uint and 0 upper nibbles)
                    _0x08Mask)); // 0x8

            // result looks like this
            // 0H 0L 0H 0L 0H 0L 0H 0L (H = high nibble, L = lower nibble)
            // now shift high bytes left by 4 bit and interleave with lower nibble.
            Vector128<uint> highNibbles = Sse2.ShiftLeftLogical128BitLane(Sse2.ShiftLeftLogical(stretchedNibbles, 4), 1); // LITTLE ENDIAN!!!

            // highNibbles looks like this
            // 00 H0 L0 H0 L0 H0 L0 H0 (H = high nibble, L = lower nibble)
            // now combine higher and lower nibbles into hex decoded bytes.
            Vector128<uint> combinedNibbles = Sse2.Or(highNibbles, stretchedNibbles);

            // combinedNibbles looks like this
            // 0H HL LH HL LH HL LH HL where every second byte is valid.
            // 0A AA AB BB BC CC CD DD ...
            Vector128<byte> result = Ssse3.Shuffle(combinedNibbles.AsByte(), _shuffleData);

            // result looks like this:
            // AA BB CC DD EE FF GG HH 00 00 00 00 00 00 00 00
            Vector64<byte> hexDecodedBytes = Vector128.GetLower(result);

            // hexDecodedBytes looks like this :)
            // AA BB CC DD EE FF GG HH
            *(ulong*)output = Vector64.ToScalar(hexDecodedBytes.AsUInt64());
        }
        if (i > 0)
        {
            HexConverterHwIntrinsicsDefault.Unhexlify(input, i, output, workspaceBuffer);
        }
    }
}
