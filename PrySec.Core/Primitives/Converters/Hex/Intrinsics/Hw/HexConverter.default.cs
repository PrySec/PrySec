using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal class HexConverterHwIntrinsicsDefault : IHexConverterImplementation
{
    public static int InputBlockSize => 2;

    public static int OutputBlockSize => 1;

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output)
    {
        for (; inputSize - sizeof(ulong) >= 0; inputSize -= sizeof(ulong), input += sizeof(ulong), output += sizeof(ulong) / 2)
        {
            ulong input8 = *(ulong*)input;
            // (input & 0xF) + (input >> 6) | ((input >> 3) & 0x8);
            // AH AL BH BL CH CL DH DL
            ulong stretchedNibbles8 = ((input8 & 0x0F0F0F0F_0F0F0F0FuL) + ((input8 >>> 6) & 0x03030303_03030303uL)) | ((input8 >>> 3) & 0x08080808_08080808uL);
            DebugUtils.PrintBufferDebug(&stretchedNibbles8, 8);
            // 00 AA 00 BB 00 CC 00 DD
            ulong oneOne8 = (stretchedNibbles8 | (stretchedNibbles8 >>> 4)) & 0x00FF00FF00_FF00FFuL;
            DebugUtils.PrintBufferDebug(&oneOne8, 8);
            // 00 00 AA BB 00 00 CC DD
            ulong twoTwo8 = (oneOne8 | (oneOne8 >>> 8)) & 0x0000FFFF_0000FFFFuL;
            DebugUtils.PrintBufferDebug(&twoTwo8, 8);
            // 00 00 XX XX AA BB CC DD
            ulong fourFour8 = twoTwo8 | (twoTwo8 >>> 16);
            DebugUtils.PrintBufferDebug(&fourFour8, 8);
            *(uint*)output = (uint)fourFour8;
        }
        for (Size_T i = 0; i < inputSize; i += 2, input += 2, output++)
        {
            byte upper = *input;
            byte lower = *(input + 1);
            int upperNibble = ((upper & 0xF) + (upper >> 6) | ((upper >> 3) & 0x8));
            int lowerNibble = ((lower & 0xF) + (lower >> 6) | ((lower >> 3) & 0x8));
            *output = (byte)((upperNibble << 4) | lowerNibble);
        }
    }
}
