﻿//#define custom

using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Security.Cryptography.Hashing.Blake2;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using Testing;

const uint _WARMUP = 1_000_000;
const uint _ITERATIONS = 25_000_000;

unsafe
{
    byte* ptr = (byte*)NativeMemory.AllocZeroed(65536);
    for (int i = 0; i < _WARMUP; i++)
    {
        Unsafe.InitBlockUnaligned(ptr, 0, 65536);
    }
    Stopwatch sw = Stopwatch.StartNew();
    for (int i = 0; i < _ITERATIONS; i++)
    {
        Unsafe.InitBlockUnaligned(ptr, 0, 65536);
    }
    sw.Stop();
    Console.WriteLine(sw.Elapsed);
    Console.WriteLine($"That's {sw.ElapsedMilliseconds / (double)_ITERATIONS} ms / it");
    Console.WriteLine($"Or {(double)_ITERATIONS / sw.ElapsedMilliseconds * 1000} it / s");
    NativeMemory.Free(ptr);
}

/*

Unsafe.InitBlockUnaligned(ptr, 0, 65536);

00:00:54.4558939
That's 0.0021782 ms / it
Or 459094.66531998897 it / s


Span.Fill:

00:00:54.4351540
That's 0.0021774 ms / it
Or 459263.3416000735 it / s

 */

return;

const uint WARMUP = 10_000;
const uint ITERATIONS = 250_000;

unsafe
{
    string str = new('A', 100000);
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

00:xx:xx
That's 0.214306 ms / hash
Or 4666.2249307065595 hashes / s

PrySec AVX2
00:00:45.2073221
That's 0.180828 ms / it
Or 5530.117017276085 it / s

Prysec default
00:01:06.7934403
That's 0.267172 ms / it
Or 3742.9071908732953 it / s

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