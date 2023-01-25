using BenchmarkDotNet.Attributes;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using System;
using PrySec.Core.Memory.MemoryManagement;
using System.Runtime.CompilerServices;
using Microsoft.Diagnostics.Tracing.Parsers.JScript;

namespace Testing;

public interface I
{
    int Foo { get; }
}

public class C : I
{
    public int Foo { get; }

    public C(int foo)
    {
        Foo = foo;
    }
}

public static class T
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Direct(C c) => c.Foo;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Interface(I i) => i.Foo;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int Generic<TI>(TI t) where TI : I => t.Foo;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int RefDirect(ref C c) => c.Foo;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int RefInterface(ref I i) => i.Foo;

    [MethodImpl(MethodImplOptions.NoInlining)]
    public static int RefGeneric<TC>(ref TC t) where TC : I => t.Foo;
}

public class Test
{
    private C c = new(42);

    [Benchmark]
    public int TestDirect() => T.Direct(c);

    [Benchmark]
    public int TestInterface() => T.Interface(c);

    [Benchmark]
    public int Generic() => T.Generic(c);

    [Benchmark]
    public int TestRef() => T.RefDirect(ref c);

    [Benchmark]
    public int TestRefInterface()
    {
        I i = c;
        return T.RefInterface(ref i);
    }

    [Benchmark]
    public int TestRefGeneric() => T.RefGeneric(ref c);
}