using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal unsafe class HexConverterHwIntrinsicsDefault__EffectiveArch
{
    public static delegate*<byte*, Size_T, byte*, void> Unhexlify { get; }

    static HexConverterHwIntrinsicsDefault__EffectiveArch()
    {
        Unhexlify = BitConverter.IsLittleEndian switch
        {
            true => Use<HexConverterHwIntrinsicsDefaultLittleEndian>(),
            false => Use<HexConverterHwIntrinsicsDefaultBigEndian>(),
        };
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static delegate*<byte*, Size_T, byte*, void> Use<T>() where T : IHexConverterImplementation => 
        &T.Unhexlify;
}
