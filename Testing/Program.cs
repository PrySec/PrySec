﻿//#define custom

using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Core.Simd;
using PrySec.Security.Cryptography.Hashing.Blake2;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using Testing;


const uint WARMUP = 10_000;
const uint ITERATIONS = 1_000_000;

unsafe
{
    string str = new string('A', 100000);
    int strLength = str.Length;
    DeterministicSpan<byte> span = DeterministicSpan<byte>.Allocate(strLength);
    fixed (char* pStr = str)
    {
        Unsafe.CopyBlockUnaligned(span.BasePointer, pStr, (uint)strLength);
        Console.WriteLine($"Calling Test Methods {ITERATIONS} times with additional warmup of {WARMUP} ...");
        Console.WriteLine();
        // setup

        // warmup
        Blake2b b = new Blake2b();
        for (uint i = 0; i < WARMUP; i++)
        {
            using var _ = b.ComputeHash<byte, DeterministicSpan<byte>, DeterministicSpan<byte>>(ref span);
        }
        Stopwatch stopwatch = new();
        stopwatch.Start();
        for (uint i = 0; i < ITERATIONS; i++)
        {
            using var _ = b.ComputeHash<byte, DeterministicSpan<byte>, DeterministicSpan<byte>>(ref span);
        }
        stopwatch.Stop();
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / (double)ITERATIONS} ms / it");
        Console.WriteLine($"Or {(double)ITERATIONS / stopwatch.ElapsedMilliseconds * 1000} it / s");
        Console.WriteLine();
    }
}

/*
 * 
 * 
pmdbs2x blake:

00:03:34.3069093
That's 0.214306 ms / hash
Or 4666.2249307065595 hashes / s

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