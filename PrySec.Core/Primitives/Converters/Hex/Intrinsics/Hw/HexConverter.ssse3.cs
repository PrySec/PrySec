using PrySec.Core.NativeTypes;
using System;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal class HexConverterHwIntrinsicsSsse3 : IHexConverterImplementation
{
    public static int InputBlockSize => 16;

    public static int OutputBlockSize => 8;

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output, byte* workspaceBuffer)
    {
        Size_T i = inputSize;
        for (; i - InputBlockSize >= 0; i += InputBlockSize, input += InputBlockSize, output += OutputBlockSize)
        {
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector128<byte> vInput = Sse2.LoadVector128(input + i);
            Vector128<uint> xFmask = Vector128.Create(0x0F0F0F0Fu);
            Vector128<uint> x8mask = Vector128.Create(0x08080808u);
            Vector128<uint> sixRightShiftMask = Vector128.Create(0x03030303u);
            Vector128<uint> uint32Input = Vector128.As<byte, uint>(vInput);

            // map ASCII hex values to byte values 0 - 15 using
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector128<uint> stretchedNibbles = Sse2.Or(
                Sse2.Add(// (input & 0xF) + (input >> 6)
                    Sse2.And(uint32Input, xFmask), // (input & 0xF)
                    Sse2.And(Sse2.ShiftRightLogical(uint32Input, 6), sixRightShiftMask)),// (input >> 6) (shift as uint and 0 upper 6 bits in every byte)
                Sse2.And( // ((input >> 3) & 0x8);
                    Sse2.And(Sse2.ShiftRightLogical(uint32Input, 3), xFmask), // (input >> 3) (shift as uint and 0 upper nibbles)
                    x8mask)); // 0x8

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
            // now set invalid bytes to zero using bitmask
            Vector128<uint> zeroMask = Vector128.Create(0xFF00FF00u); // LITTLE ENDIAN!!!
            Vector128<uint> everySecondByteIsValid = Sse2.And(combinedNibbles, zeroMask);

            // everySecondByteIsValid looks like this
            // 00 HL 00 HL 00 HL 00 HL where every second byte is valid.
            // now we need to fill the gaps...
            // duplicate and expand vlid bytes to the left.
            Vector128<uint> everyByteIsDuplicated = Sse2.Or(Sse2.ShiftRightLogical128BitLane(everySecondByteIsValid, 1), everySecondByteIsValid);

            // everyByteIsDuplicated looks like this
            // AA AA BB BB CC CC DD DD where AA to DD may hold any byte value.
            // now remove duplicates with another bitmask, alernating between high and low bytes for 16 bit integers.
            Vector128<uint> uInt16Mask = Vector128.Create(0xFF0000FFu);
            Vector128<short> separatedUin16HiLoBytes = Vector128.As<uint, short>(Sse2.And(everyByteIsDuplicated, uInt16Mask));

            // separatedUin16HiLoBytes looks like this
            // AA 00 00 BB CC 00 00 DD
            // how horizontally add adjacent 16 bit integers and pack everything into the high 64 bit.
            Vector128<short> result = Ssse3.HorizontalAdd(separatedUin16HiLoBytes, separatedUin16HiLoBytes);

            // result looks like this:
            // AA BB CC DD EE FF GG HH AA BB CC DD EE FF GG HH
            // we can now store the upper 8 bytes.
            Vector64<short> hexDecodedBytes = Vector128.GetUpper(result);

            // hexDecodedBytes looks like this :)
            // AA BB CC DD EE FF GG HH
            *(ulong*)output = Vector64.ToScalar(Vector64.As<short, ulong>(hexDecodedBytes));
        }
        if (i > 0)
        {
            HexConverterHwIntrinsicsDefault.Unhexlify(input, i, output, workspaceBuffer);
        }
    }
}
