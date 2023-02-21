using System.Runtime.Intrinsics;

namespace PrySec.Core.Primitives.Converters.Hex.Intrinsics.Hw;

internal unsafe abstract class HexConverter128BitBase
{
    protected static readonly Vector128<uint> _0x03Mask;

    protected static readonly Vector128<uint> _0x08Mask;

    protected static readonly Vector128<uint> _0x0fMask;

    static HexConverter128BitBase()
    {
        _0x03Mask = Vector128.Create(0x03030303u);
        _0x08Mask = Vector128.Create(0x08080808u);
        _0x0fMask = Vector128.Create(0x0F0F0F0Fu);
    }
}
