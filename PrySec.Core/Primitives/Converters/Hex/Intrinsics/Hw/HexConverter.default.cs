using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal class HexConverterHwIntrinsicsDefault : IHexConverterImplementation
{
    public static int InputBlockSize => 2;

    public static int OutputBlockSize => 1;

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output)
    {
        // TODO: use word-size
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
