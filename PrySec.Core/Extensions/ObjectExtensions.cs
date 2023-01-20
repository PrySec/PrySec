using System.Runtime.CompilerServices;

namespace PrySec.Core.Extensions;

public static class ObjectExtensions
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static T As<T>(this object o) => (T)o;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static T AsUnsafe<T>(this object o) where T : class => Unsafe.As<T>(o);
}
