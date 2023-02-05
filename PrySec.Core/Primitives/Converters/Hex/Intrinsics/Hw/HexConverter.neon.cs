using PrySec.Core.NativeTypes;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal class HexConverterHwIntrinsicsNeon : IHexConverterImplementation
{
    public static int InputBlockSize => 16;

    public static int OutputBlockSize => 8;

    public static unsafe void Unhexlify(byte* input, Size_T inputSize, byte* output, byte* workspaceBuffer)
    {
        Size_T i = inputSize;
        // TODO: impl
        if (i > 0)
        {
            HexConverterHwIntrinsicsDefault.Unhexlify(input, i, output, workspaceBuffer);
        }
    }
}
