using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics;

internal static unsafe class HexConverter__EffectiveArch
{
    /// <summary>
    /// void Unhexlify(byte* input, Size_T inputSize, byte* output, Size_T outputSize)
    /// </summary>
    public static delegate*<byte*, Size_T, byte*, void> DispatchUnhexlify { get; private set; }

    private static readonly int _inputBlockSize;

    static HexConverter__EffectiveArch()
    {
        _inputBlockSize = 0 switch
        {
            _ when Avx2.IsSupported => Use<HexConverterHwIntrinsicsAvx2>(),
            _ when Ssse3.IsSupported => Use<HexConverterHwIntrinsicsSsse3>(),
            _ when Sse2.IsSupported => Use<HexConverterHwIntrinsicsSse2>(),
            _ when AdvSimd.IsSupported => Use<HexConverterHwIntrinsicsNeon>(),
            _ => Use<HexConverterHwIntrinsicsDefault>()
        };
    }

    public static int Use<T>() where T : IHexConverterImplementation
    {
        DispatchUnhexlify = &T.Unhexlify;
        return T.InputBlockSize;
    }
}
