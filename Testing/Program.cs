#define custom

using PrySec.Base.Memory;
using PrySec.Base.Primitives.Converters;
using PrySec.Security.Cryptography.Hashs;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Diagnostics;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using System.Text;

const int WARMUP = 100_000;
const int ITERATIONS = 25_000_000;

unsafe
{
    const string str = "abc";
    int strLength = str.Length;
    fixed (char* pStr = str)
    {
#if custom
        int rawUtf8Length = Encoding.UTF8.GetByteCount(pStr, strLength);
        using UnmangedSpan<byte> buffer = new(rawUtf8Length);
        byte* utf8Bytes = (byte*)buffer.BasePointer;
        Encoding.UTF8.GetBytes(pStr, strLength, utf8Bytes, rawUtf8Length);
#else
        SHA1Managed sha = new();
        byte[] buffer = Encoding.UTF8.GetBytes(str);
#endif
        Console.WriteLine("Warmup...");
        for (int i = 0; i < WARMUP; i++)
        {
#if custom
            using DeterministicSpan<byte> result = Sha1Scp.Digest(buffer);
            Console.WriteLine("Calculated result is:");
            Console.WriteLine(Convert.ToHexString(result.AsSpan()));
            Console.WriteLine("Expected result was:");
            Console.WriteLine("A9993E364706816ABA3E25717850C26C9CD0D89D");
            return;
#else
            byte[] result = sha.ComputeHash(buffer);
            Console.WriteLine(Convert.ToHexString(result));
#endif
        }
        Stopwatch stopwatch = new Stopwatch();
        Console.WriteLine("Measuring...");
        stopwatch.Start();
        for (int i = 0; i < ITERATIONS; i++)
        {
#if custom
            using DeterministicSpan<byte> result = Sha1Scp.Digest(buffer);
#else
            sha.ComputeHash(buffer);
#endif
        }
        stopwatch.Stop();
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / (double)ITERATIONS} ms / hash");
        Console.WriteLine($"Or {(double)ITERATIONS / stopwatch.ElapsedMilliseconds * 1000} hashes / s");
    }
}

/*
Timing:

00:00:18.6424317
That's 0.00074568 ms / hash
Or 1341057.826413475 hashes / s

------------------------------------------------

BUILT-IN Timing:

00:00:23.6836672
That's 0.00094732 ms / hash
Or 1055609.5089304566 hashes / s

------------------------------------------------

pmdbs2XNative Timing:

00:00:35.2724371
That's 0.00141088 ms / hash
Or 708777.500567022 hashes / s

 */

static unsafe void PrintBuffer(uint* buffer)
{
    for (int i = 0; i < 4; i++)
    {
        Console.WriteLine(buffer[i].ToString("X8"));
    }
}
