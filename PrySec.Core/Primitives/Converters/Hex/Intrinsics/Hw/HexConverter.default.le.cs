using PrySec.Core.NativeTypes;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal class HexConverterHwIntrinsicsDefaultLittleEndian : IHexConverterImplementation
{
    public static int SimdInputBlockSize => -1;

    public static int SimdOutputBlockSize => -1;

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output)
    {
        for (; inputSize >= sizeof(ulong); inputSize -= sizeof(ulong), input += sizeof(ulong), output += sizeof(uint))
        {
            ulong input8 = *(ulong*)input;

            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            // 01 02 03 04 05 06 07 08
            // 08 07 06 05 04 03 02 01 in LE
            ulong stretchedNibbles8 = ((input8 & 0x0F0F0F0F_0F0F0F0FuL) + ((input8 >>> 6) & 0x03030303_03030303uL)) | ((input8 >>> 3) & 0x08080808_08080808uL);

            // 78 00 56 00 34 00 12 00
            ulong oneOne8 = (stretchedNibbles8 | (stretchedNibbles8 << 12)) & 0xFF00FF00_FF00FF00uL;

            // 78 56 00 00 34 12 00 00
            ulong twoTwo8 = (oneOne8 | (oneOne8 << 8)) & 0xFFFF0000_FFFF0000uL;

            // 78 56 34 12 XX XX 00 00
            ulong fourFour8 = twoTwo8 | (twoTwo8 << 16);

            // because LE
            *(uint*)output = *(((uint*)&fourFour8) + 1);
        }
        if (inputSize >= sizeof(uint))
        {
            uint input4 = *(uint*)input;

            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            // 01 02 03 04
            // 04 03 02 01 in LE
            uint stretchedNibbles4 = ((input4 & 0x0F0F0F0Fu) + ((input4 >>> 6) & 0x03030303u)) | ((input4 >>> 3) & 0x08080808u);

            // 34 00 12 00
            uint oneOne4 = (stretchedNibbles4 | (stretchedNibbles4 << 12)) & 0xFF00_FF00u;

            // 34 12 XX 00
            uint twoTwo4 = oneOne4 | (oneOne4 << 8);

            // because LE
            *(ushort*)output = *(((ushort*)&twoTwo4) + 1);

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
            // 00 00 01 02
            // 00 00 02 01 in LE
            uint stretchedNibbles2 = ((input2 & 0x0000_0F0Fu) + ((input2 >>> 6) & 0x0000_0303u)) | ((input2 >>> 3) & 0x0000_0808u);

            // 00 X0 12 00
            uint oneOne2 = stretchedNibbles2 | (stretchedNibbles2 << 12);

            // because LE
            *output = *(((byte*)&oneOne2) + 1);
        }
        // ignore trailing single bytes (can't be valid hex)
    }
}
