using PrySec.Core.NativeTypes;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal class HexConverterHwIntrinsicsDefaultBigEndian : IHexConverterImplementation
{
    public static int SimdInputBlockSize => -1;

    public static int SimdOutputBlockSize => -1;

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output)
    {
        for (; inputSize >= sizeof(ulong); inputSize -= sizeof(ulong), input += sizeof(ulong), output += sizeof(uint))
        {
            ulong input8 = *(ulong*)input;

            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            // 01 02 03 04 05 06 07 08 in BE
            ulong stretchedNibbles8 = ((input8 & 0x0F0F0F0F_0F0F0F0FuL) + ((input8 >>> 6) & 0x03030303_03030303uL)) | ((input8 >>> 3) & 0x08080808_08080808uL);

            // 00 12 00 34 00 56 00 78
            ulong oneOne8 = (stretchedNibbles8 | (stretchedNibbles8 >>> 4)) & 0x00FF00FF_00FF00FFuL;

            // 00 00 12 34 00 00 56 78
            ulong twoTwo8 = (oneOne8 | (oneOne8 >>> 8)) & 0x0000FFFF_0000FFFFuL;

            // 00 00 XX XX 12 34 56 78
            ulong fourFour8 = twoTwo8 | (twoTwo8 >>> 16);

            *(uint*)output = (uint)fourFour8;
        }
        if (inputSize >= sizeof(uint))
        {
            uint input4 = *(uint*)input;

            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            // 01 02 03 04 in BE
            uint stretchedNibbles4 = ((input4 & 0x0F0F0F0Fu) + ((input4 >>> 6) & 0x03030303u)) | ((input4 >>> 3) & 0x08080808u);

            // 00 12 00 34
            uint oneOne4 = (stretchedNibbles4 | (stretchedNibbles4 >>> 4)) & 0x00FF00FFu;

            // 00 XX 12 34
            uint twoTwo4 = oneOne4 | (oneOne4 >>> 8);

            *(ushort*)output = (ushort)twoTwo4;

            // increment
            inputSize -= sizeof(uint);
            input += sizeof(uint);
            output += sizeof(ushort);
        }
        if (inputSize >= sizeof(ushort))
        {
            // operate on DWORDs (with 16 bit data)
            uint input2 = *(ushort*)input;

            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            // 00 00 01 02 in BE
            uint stretchedNibbles2 = ((input2 & 0x0F0F0F0Fu) + ((input2 >>> 6) & 0x03030303u)) | ((input2 >>> 3) & 0x08080808u);

            // 00 00 0X 12
            uint oneOne2 = stretchedNibbles2 | (stretchedNibbles2 >>> 4);

            *output = (byte)oneOne2;
        }
        // ignore trailing single bytes (can't be valid hex)
    }
}
