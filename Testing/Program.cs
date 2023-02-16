using BenchmarkDotNet.Running;
using PrySec.Core.HwPrimitives;
using PrySec.Core.IO;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using PrySec.Core.Native.UnixLike;
using PrySec.Security.Cryptography.Hashing.Blake2;
using PrySec.Security.MemoryProtection.Native.Ntos.DPApi;
using PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;
using PrySec.Security.MemoryProtection.Native.Posix.SysMMan;
using PrySec.Security.MemoryProtection.Portable;
using PrySec.Security.MemoryProtection.Portable.XofOtp;
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading;
using Testing;

unsafe
{
    byte* input = stackalloc byte[16];
    for (int i = 1; i < 16; i+=2)
    {
        input[i] = (byte)i;
    }

    byte* t = stackalloc byte[16];
    for (int i = 0; i < 8; i++)
    {
        t[i] = (byte)((2 * i) + 1);
    }
    Vector128<byte> exp = Sse2.LoadVector128(t);

    Vector128<byte> v = Sse2.LoadVector128(input);
    Console.WriteLine($"Input {v}");

    byte[] shuffleData = new byte[16]
    {
        0x01, 0x03, 0x05, 0x07, 0x09, 0x0b, 0x0d, 0x0f,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };

    Vector128<byte> shuffle_mask;

    fixed (byte* p = shuffleData)
    {
        shuffle_mask = Sse2.LoadVector128(p);
    }

    Vector128<byte> shuffled = Ssse3.Shuffle(v, shuffle_mask);
    Console.WriteLine(shuffled);
    //Vector128<byte> result = Avx2.Permute4x64(shuffled.AsInt64(), AvxPrimitives._MM_SHUFFLE(3, 1, 2, 0)).AsByte();
    //Console.WriteLine(result);
    Console.WriteLine($"Expecting\n{exp}");
}

return;

using ProcfsMapsParser mapsParser = new(256);
using ProcfsMemoryRegionInfoList list = mapsParser.QueryProcfs();

return;

Span<byte> buffer = stackalloc byte[100];
using Stream st = File.OpenRead("test.txt");
using AsciiStream a = new(16, st);
while (true)
{
    int bytesWritten = a.ReadLine(buffer);
    if (bytesWritten <= 0)
    {
        break;
    }
    Span<byte> line = buffer[..bytesWritten];
    Console.WriteLine(Encoding.ASCII.GetString(line));
}
Console.WriteLine("done.");
return;

unsafe
{
    byte* b = stackalloc byte[8];
    b[0] = 0;
    b[1] = 1;
    b[2] = 2;
    b[3] = 3;
    b[4] = 4;
    b[5] = 5;
    b[6] = 0;
    b[7] = 7;
    ulong u8 = BinaryUtils.ReadUInt64BigEndian((ulong*)b);//BinaryPrimitives.ReadUInt64BigEndian(new Span<byte>(&value, 8));
    ulong zeroMask = BinaryUtils.MaskZeroByte(u8);
    if (zeroMask != 0uL)
    {
        Console.WriteLine($"0x{u8:x16} contains one or more zero bytes!");
        int index = 0;
        BinaryUtils.BitScanReverse(&index, zeroMask);
        Console.WriteLine($"Byte offset {7 - (index / 8)} is the first zero byte!");
    }
    else
    {
        System.Console.WriteLine($"0x{u8:x16} has no zero bytes!");
    }
}
return;

unsafe
{
    MemoryManager.UseImplementation<NativeMemoryManager>();

    MProtectedMemory__Internal<byte> mem = MProtectedMemory__Internal<byte>.Allocate(128);
    byte[] bytes = Encoding.ASCII.GetBytes("Oh gawd send help lol xD");
    using (IMemoryAccess<byte> access = mem.GetAccess())
    {
        bytes.CopyTo(access.AsSpan());
    }
    //while (true)
    //{
    //    Console.ReadLine();
    //}
    Console.WriteLine($"{mem.NativeHandle:x16}");
    string s = File.ReadAllText("/proc/self/maps");
    Console.WriteLine(s);
}

static unsafe int QueryProcSelf(nint handle)
{
    using Stream s = File.OpenRead("/proc/self/maps");
    Console.WriteLine(s.Length);
    return 0;
}

#if false

return;

const uint WARMUP = 10_000;
const uint ITERATIONS = 500_000;

unsafe
{
    string str = new('A', 100000);
    int strLength = str.Length;
    DeterministicMemory<byte> span = DeterministicMemory<byte>.Allocate(strLength);
    fixed (char* pStr = str)
    {
        Unsafe.CopyBlockUnaligned(span.DataPointer, pStr, (uint)strLength);
        Console.WriteLine($"Calling Test Methods {ITERATIONS} times with additional warmup of {WARMUP} ...");
        Console.WriteLine();
        // setup

        // warmup
        Blake2bScp b = new();
        for (uint i = 0; i < WARMUP; i++)
        {
            using DeterministicMemory<byte> _ = b.ComputeHash(ref span);
        }
        Stopwatch stopwatch = new();
        stopwatch.Start();
        for (uint i = 0; i < ITERATIONS; i++)
        {
            using DeterministicMemory<byte> _ = b.ComputeHash(ref span);
        }
        stopwatch.Stop();
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / (double)ITERATIONS} ms / it");
        Console.WriteLine($"Or {(double)ITERATIONS / stopwatch.ElapsedMilliseconds * 1000} it / s");
        Console.WriteLine($"Or {ITERATIONS * Encoding.UTF8.GetByteCount(str) / 1_000_000 / stopwatch.Elapsed.TotalSeconds} MB / s");
        Console.WriteLine();
    }
}
#endif
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