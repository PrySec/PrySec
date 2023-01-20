namespace PrySec.Core.Extensions;

public static class ObjectExtensions
{
    public static T As<T>(this object o) => (T)o;
}
