using PrySec.Core.NativeTypes;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal unsafe interface IHexConverterImplementation
{
    static abstract int InputBlockSize { get; }

    static abstract int OutputBlockSize { get; }

    static abstract void Unhexlify(byte* input, Size_T inputSize, byte* output);
}
