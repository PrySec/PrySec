using System.Runtime.CompilerServices;

namespace PrySec.Core.Primitives;

public static class Extensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe int ToInt32(this bool b) => *(byte*)&b;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe uint ToDword(this bool b) => *(byte*)&b;
}