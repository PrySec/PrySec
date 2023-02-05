using PrySec.Core.NativeTypes;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal class HexConverterHwIntrinsicsAvx2 : IHexConverterImplementation
{
    public static int InputBlockSize => 32;

    public static int OutputBlockSize => 16;

    // TODO: use permutation intrinsics!
    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output, byte* workspaceBuffer)
    {
        Size_T i = inputSize;
        for ( ; i - InputBlockSize > 0; i -= InputBlockSize, input += InputBlockSize, output += OutputBlockSize)
        {
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector256<byte> vInput = Avx.LoadVector256(input);
            Vector256<uint> xFmask = Vector256.Create(0x0F0F0F0Fu);
            Vector256<uint> x8mask = Vector256.Create(0x08080808u);
            Vector256<uint> sixRightShiftMask = Vector256.Create(0x03030303u);
            Vector256<uint> uint32Input = Vector256.As<byte, uint>(vInput);

            // map ASCII hex values to byte values 0 - 15 using
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            Vector256<uint> stretchedNibbles = Avx2.Or(
                Avx2.Add(// (input & 0xF) + (input >> 6)
                    Avx2.And(uint32Input, xFmask), // (input & 0xF)
                    Avx2.And(Avx2.ShiftRightLogical(uint32Input, 6), sixRightShiftMask)),// (input >> 6) (shift as uint and 0 upper 6 bits in every byte)
                Avx2.And( // ((input >> 3) & 0x8);
                    Avx2.And(Avx2.ShiftRightLogical(uint32Input, 3), xFmask), // (input >> 3) (shift as uint and 0 upper nibbles)
                    x8mask)); // 0x8

            // result looks like this
            // 0H 0L 0H 0L 0H 0L 0H 0L (H = high nibble, L = lower nibble)
            // now shift high bytes left by 4 bit and interleave with lower nibble.
            Vector256<uint> highNibbles = Avx2.ShiftLeftLogical128BitLane(
                Avx2.ShiftLeftLogical(stretchedNibbles, 4), 1); // LITTLE ENDIAN!!!

            // highNibbles looks like this
            // 00 H0 L0 H0 L0 H0 L0 H0 (H = high nibble, L = lower nibble)
            // now combine higher and lower nibbles into hex decoded bytes.
            Vector256<uint> combinedNibbles = Avx2.Or(highNibbles, stretchedNibbles);

            // combinedNibbles looks like this
            // 0H HL LH HL LH HL LH HL where every second byte is valid.
            // now set invalid bytes to zero using bitmask
            Vector256<uint> zeroMask = Vector256.Create(0xFF00FF00u); // LITTLE ENDIAN!!!
            Vector256<uint> everySecondByteIsValid = Avx2.And(combinedNibbles, zeroMask);

            // everySecondByteIsValid looks like this
            // 00 HL 00 HL 00 HL 00 HL where every second byte is valid.
            // now we need to fill the gaps...
            // duplicate and expand valid bytes to the left (in network byte order).
            Vector256<uint> everyByteIsDuplicated = Avx2.Or(Avx2.ShiftRightLogical128BitLane(everySecondByteIsValid, 1), everySecondByteIsValid);

            // everyByteIsDuplicated looks like this
            // AA AA BB BB CC CC DD DD where AA to DD may hold any byte value.
            // now remove duplicates with another bitmask, alernating between high and low bytes for 16 bit integers.
            Vector256<uint> uInt16Mask = Vector256.Create(0xFF0000FFu);
            Vector256<short> separatedUin16HiLoBytes = Vector256.As<uint, short>(Avx2.And(everyByteIsDuplicated, uInt16Mask));

            // separatedUin16HiLoBytes looks like this
            // AA 00 00 BB CC 00 00 DD
            // how horizontally add adjacent 16 bit integers and pack everything into the high 64 bit.
            Vector256<short> result = Avx2.HorizontalAdd(separatedUin16HiLoBytes, separatedUin16HiLoBytes);

            // result looks like this:
            // AA BB CC DD EE FF GG HH AA BB CC DD EE FF GG HH II JJ KK LL MM NN OO PP II JJ KK LL MM NN OO PP
            // we can now store the upper 8 bytes and the 8 bytes starting at index 16.
            Avx.Store(workspaceBuffer, Vector256.AsByte(result));
        }
        if (i > 0uL)
        {
            HexConverterHwIntrinsicsSsse3.Unhexlify(input, i, output, workspaceBuffer);
        }
    }
}
