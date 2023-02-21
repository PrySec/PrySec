using PrySec.Core.NativeTypes;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal unsafe interface IHexConverterImplementation
{
    static abstract int SimdInputBlockSize { get; }

    static abstract int SimdOutputBlockSize { get; }

    static abstract void Unhexlify(byte* input, Size_T inputSize, byte* output);
}