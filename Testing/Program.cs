//#define custom

using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using System;
using System.Diagnostics;
using Testing;

Test.Asdf(0);

return;

const uint WARMUP = 10_000_000;
const uint ITERATIONS = 2_500_000_000;

unsafe
{
    string str = new('A', 10000);
    int strLength = str.Length;
    fixed (char* pStr = str)
    {
        Console.WriteLine($"Calling Test Methods {ITERATIONS} times with additional warmup of {WARMUP} ...");
        Console.WriteLine();
        // setup

        // warmup
        for (uint i = 0; i < WARMUP; i++)
        {
            _ = InstanceTest.Test(i);
        }
        Stopwatch stopwatch = new();
        stopwatch.Start();
        for (uint i = 0; i < ITERATIONS; i++)
        {
            _ = InstanceTest.Test(i);
        }
        stopwatch.Stop();
        Console.WriteLine("private static instance call forward:");
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / (double)ITERATIONS} ms / it");
        Console.WriteLine($"Or {(double)ITERATIONS / stopwatch.ElapsedMilliseconds * 1000} it / s");
        Console.WriteLine();

        // setup
        DelegateTest.Use<DelegateTestImpl>();
        // warmup
        for (uint i = 0; i < WARMUP; i++)
        {
            _ = DelegateTest.Test(i);
        }
        stopwatch = new();
        stopwatch.Start();
        for (uint i = 0; i < ITERATIONS; i++)
        {
            _ = DelegateTest.Test(i);
        }
        stopwatch.Stop();
        Console.WriteLine("delegate call:");
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / (double)ITERATIONS} ms / it");
        Console.WriteLine($"Or {(double)ITERATIONS / stopwatch.ElapsedMilliseconds * 1000} it / s");
        Console.WriteLine();

        // setup
        DelegateTestExpressionTree.Use<DelegateTestImpl>();
        // warmup
        for (uint i = 0; i < WARMUP; i++)
        {
            _ = DelegateTestExpressionTree.Test(i);
        }
        stopwatch = new();
        stopwatch.Start();
        for (uint i = 0; i < ITERATIONS; i++)
        {
            _ = DelegateTestExpressionTree.Test(i);
        }
        stopwatch.Stop();
        Console.WriteLine("delegate call via expression tree:");
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / (double)ITERATIONS} ms / it");
        Console.WriteLine($"Or {(double)ITERATIONS / stopwatch.ElapsedMilliseconds * 1000} it / s");
        Console.WriteLine();

        // setup
        FuctionPointerTestWithProperty.Use<DelegateTestImpl>();
        // warmup
        for (uint i = 0; i < WARMUP; i++)
        {
            _ = FuctionPointerTestWithProperty.Test(i);
        }
        stopwatch = new();
        stopwatch.Start();
        for (uint i = 0; i < ITERATIONS; i++)
        {
            _ = FuctionPointerTestWithProperty.Test(i);
        }
        stopwatch.Stop();
        Console.WriteLine("static function pointer call:");
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / (double)ITERATIONS} ms / it");
        Console.WriteLine($"Or {(double)ITERATIONS / stopwatch.ElapsedMilliseconds * 1000} it / s");
        Console.WriteLine();
    }
}

/*

=======================================

Timing SHA2:

00:03:47.6726719
That's 0.0910688 ms / hash
Or 10980.709090270213 hashes / s

------------------------------------------------

BUILT-IN Timing:

00:02:04.2549446
That's 0.0497016 ms / hash
Or 20120.076617251758 hashes / s

------------------------------------------------

pmdbs2XNative Timing:

00:00:35.2724371
That's 0.00141088 ms / hash
Or 708777.500567022 hashes / s

======================================

SHA-1

unoptimized custom:

00:00:14.7704745
That's 0.0005908 ms / hash
Or 1692620.1760324985 hashes / s

using seperate variables:

00:00:14.3765852
That's 0.00057504 ms / hash
Or 1739009.4602114637 hashes / s

-------------------------------------------

BUILT-IN Timing:

00:00:05.9739521
That's 0.00023892 ms / hash
Or 4185501.423070484 hashes / s
 */