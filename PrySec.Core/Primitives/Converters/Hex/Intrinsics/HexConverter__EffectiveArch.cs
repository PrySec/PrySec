using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics;

internal static unsafe class HexConverter__EffectiveArch
{
    /// <summary>
    /// void Unhexlify(byte* input, Size_T inputSize, byte* output, Size_T outputSize)
    /// </summary>
    private static delegate*<byte*, Size_T, byte*, byte*, void> _unhexlifyImpl;

    private static readonly int _workspaceBufferSize;

    static HexConverter__EffectiveArch()
    {
        _workspaceBufferSize = 0 switch
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
        _unhexlifyImpl = &T.Unhexlify;
        return T.InputBlockSize;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void DispatchUnhexlify(byte* input, Size_T inputSize, byte* output)
    {
        byte* workspaceBuffer = stackalloc byte[_workspaceBufferSize];
        _unhexlifyImpl(input, inputSize, output, workspaceBuffer);
    }
}
