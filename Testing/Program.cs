using BenchmarkDotNet.Running;
using PrySec.Core.HwPrimitives;
using PrySec.Core.IO;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Core.Native.UnixLike.Procfs;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives.Converters;
using PrySec.Security.Cryptography.Hashing.Blake2;
using PrySec.Security.MemoryProtection;
using PrySec.Security.MemoryProtection.Native.Ntos.DPApi;
using PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;
using PrySec.Security.MemoryProtection.Native.Posix.SysMMan;
using PrySec.Security.MemoryProtection.Portable;
using PrySec.Security.MemoryProtection.Portable.ProtectedMemory;
using PrySec.Security.MemoryProtection.Portable.XofOtp;
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security;
using System.Text;
using System.Threading;
using Testing;

unsafe
{
    IProtectedMemory<char> memory = Blake3XofOtpEncryptedMemory<char>.Allocate(20);
    using (IMemoryAccess<char> access = memory.GetAccess())
    {
        access[4] = 'u';
        access[17] = 'i';
        access[3] = 'q';
        access[18] = 'n';
        access[6] = 't';
        access[2] = 'i';
        access[1] = 'b';
        access[7] = 'o';
        access[10] = ' ';
        access[5] = 'i';
        access[12] = 'o';
        access[9] = 's';
        access[14] = 'p';
        access[13] = 'm';
        access[0] = 'U';
        access[19] = 'g';
        access[11] = 'C';
        access[16] = 't';
        access[8] = 'u';
        access[15] = 'u';
    }
    Console.WriteLine($"allocation: 0x{(nint)memory.BasePointer:x16}");
    FieldInfo? finfo = typeof(Blake3XofOtpEncryptionService).GetField("_principalKeyMemory", BindingFlags.Static | BindingFlags.NonPublic);
    ProtectedMemory<byte>? masterKey = finfo?.GetValue(null) as ProtectedMemory<byte>;
    Console.WriteLine($"master key: 0x{(masterKey?.NativeHandle ?? 0):x16}");
    while (true)
    {
        Console.WriteLine("protected!");
        Console.WriteLine("Press enter to unprotect");
        Console.ReadLine();
        using IMemoryAccess<char> _ = memory.GetAccess();
        Console.WriteLine("unprotected!");
        Console.WriteLine("Press enter to protect");
        Console.ReadLine();
    }
}

return;

unsafe
{
    MemoryManager.UseImplementation<AllocationTracker<NativeMemoryManager>>();

    using MProtectedMemory__Internal<byte> mem = MProtectedMemory__Internal<byte>.Allocate(128);
    byte[] bytes = Encoding.ASCII.GetBytes("Oh gawd send help lol xD");

    using ProcfsMapsParser procfsMapsParser = new(256);
    ProcfsMemoryRegionInfo* info = stackalloc ProcfsMemoryRegionInfo[1];
    Console.WriteLine("protected:");
    if (procfsMapsParser.TryVirtualQuery(mem.NativeHandle, info, false))
    {
        Console.WriteLine(info->ToString());
    }

    using (IMemoryAccess<byte> access = mem.GetAccess())
    {
        bytes.CopyTo(access.AsSpan());
        Console.WriteLine("unprotected:");
        if (procfsMapsParser.TryVirtualQuery(mem.NativeHandle, info, false))
        {
            Console.WriteLine(info->ToString());
        }
    }
    Console.WriteLine("protected:");
    if (procfsMapsParser.TryVirtualQuery(mem.NativeHandle, info, false))
    {
        Console.WriteLine(info->ToString());
    }
}

System.Console.WriteLine(MemoryManager.GetAllocationSnapshot());

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