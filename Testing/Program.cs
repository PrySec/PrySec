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
        Sha256Scp sha = new();
#else
        SHA256Managed sha = new();
        byte[] buffer = Encoding.UTF8.GetBytes(str);
#endif
        Stopwatch stopwatch = new Stopwatch();
        for (int i = 0; i < 10000; i++)
        {
#if custom
            using DeterministicSpan<byte> result = sha.Digest(buffer);
#else
            sha.ComputeHash(buffer);
#endif
        }
        stopwatch.Start();
        for (int i = 0; i < 10_000_000; i++)
        {
#if custom
            using DeterministicSpan<byte> result = sha.Digest(buffer);
#else
            sha.ComputeHash(buffer);
#endif
        }
        stopwatch.Stop();
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / 1_000_000d} ms / hash");
        Console.WriteLine($"Or {1_000_000d / stopwatch.ElapsedMilliseconds * 1000} hashes / s");
    }
}

/*
Timing:

00:00:08.4209627
That's 0.00842 ms / hash
Or 118764.84560570071 hashes / s
 */


static unsafe void PrintBuffer(uint* buffer)
{
    for (int i = 0; i < 4; i++)
    {
        Console.WriteLine(buffer[i].ToString("X8"));
    }
}
