using System.Linq.Expressions;
using System.Reflection;
using System.Runtime.CompilerServices;

namespace Testing;

internal static class InstanceTest
{
    private static IInstanceTest impl = new InstanceTestImpl();

    public static void Use<T>() where T : IInstanceTest, new() => impl = new T();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Test(uint i) => impl.Test(i);
}

internal class InstanceTestImpl : IInstanceTest
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public uint Test(uint i) => 0;
}

internal interface IInstanceTest
{
    uint Test(uint i);
}

////////////////////////////////////////////////////////////////////////////////

internal static class DelegateTest
{
    public static void Use<T>() where T : IDelegateTest => Test = T.Test;

    public static DelegateTestDelegate? Test { get; private set; }
}

internal static class DelegateTestExpressionTree
{
    public static void Use<T>() where T : IDelegateTest
    {
        MethodInfo? method = typeof(T).GetMethod(nameof(T.Test));
        ParameterExpression parameterExpression = Expression.Parameter(typeof(uint));
        MethodCallExpression methodExpression = Expression.Call(method!, parameterExpression);
        DelegateTestDelegate testDelegate = Expression.Lambda<DelegateTestDelegate>(methodExpression, parameterExpression).Compile();
        Test = testDelegate;
    }

    public static DelegateTestDelegate? Test { get; private set; }
}

internal static class FuctionPointerTestWithProperty
{
    public static unsafe void Use<T>() where T : IDelegateTest
    {
        Test = &T.Test;
    }

    public static unsafe delegate*<uint, uint> Test = null;
}

internal class DelegateTestImpl : IDelegateTest
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static uint Test(uint i) => 0;
}

internal interface IDelegateTest
{
    static abstract uint Test(uint i);
}

internal delegate uint DelegateTestDelegate(uint i);