using PrySec.Core.NativeTypes;
using System;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using PrySec.Core.HwPrimitives;
using System.Diagnostics;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal unsafe class HexConverterHwIntrinsicsSse2 : IHexConverterImplementation
{
    public static int InputBlockSize => 16;

    public static int OutputBlockSize => 8;

    private static readonly Vector128<byte> _selectMask;

    private static readonly Vector128<uint> _0x03Mask;

    private static readonly Vector128<uint> _0x08Mask;

    private static readonly Vector128<uint> _0x0fMask;

    static HexConverterHwIntrinsicsSse2()
    {
        byte* pSelectData = stackalloc byte[16]
        {
            0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00,
            0xff, 0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x00
        };
        _selectMask = Sse2.LoadVector128(pSelectData);
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

            stretchedNibbles.DebugPrint();

            Vector128<ulong> s = Sse2.ShiftLeftLogical(stretchedNibbles.AsUInt64(), 4);

            s.DebugPrint();

            Vector128<ulong> bytes = Sse2.Or(s, Sse2.ShiftRightLogical(stretchedNibbles.AsUInt64(), 4));

            bytes.DebugPrint();

            // result looks like this
            // 0H 0L 0H 0L 0H 0L 0H 0L (H = high nibble, L = lower nibble)
            // now shift high bytes left by 4 bit and interleave with lower nibble.
            Vector128<uint> highNibbles = Sse2.ShiftLeftLogical128BitLane(Sse2.ShiftLeftLogical(stretchedNibbles, 4), 1); // LITTLE ENDIAN!!!

            // highNibbles looks like this
            // 00 H0 L0 H0 L0 H0 L0 H0 (H = high nibble, L = lower nibble)
            // now combine higher and lower nibbles into hex decoded bytes.
            Vector128<byte> combinedNibbles = Sse2.Or(highNibbles, stretchedNibbles).AsByte();

            combinedNibbles.DebugPrint();
            Debug.WriteLine("equal to?");
            bytes.DebugPrint();

            // combinedNibbles looks like this
            // 0H HL LH HL LH HL LH HL where every second byte is valid.
            // 0A AA AB BB BC CC CD DD ...
            Vector128<byte> combinedNibblesShifted = Sse2.ShiftLeftLogical128BitLane(combinedNibbles, 1);

            combinedNibblesShifted.DebugPrint();

            // __m128i result = _mm_or_si128(_mm_and_si128(A, select_mask), _mm_andnot_si128(select_mask, A_shifted));
            Vector128<byte> result = Sse2.Or(Sse2.And(combinedNibbles, _selectMask), Sse2.AndNot(_selectMask, combinedNibblesShifted));

            result.DebugPrint();

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
