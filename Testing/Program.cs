#define custom

using PrySec.Base.Memory;
using PrySec.Base.Primitives.Converters;
using PrySec.Security.Cryptography.Hashing.Sha;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
        IUnmanaged<byte> buffer = new UnmanagedSpan<byte>(rawUtf8Length);
        byte* utf8Bytes = (byte*)buffer.BasePointer;
        Encoding.UTF8.GetBytes(pStr, strLength, utf8Bytes, rawUtf8Length);
        Sha256Scp sha = new();
#else
        SHA256CryptoServiceProvider sha = new();
        byte[] buffer = Encoding.UTF8.GetBytes(str);
#endif
        Console.WriteLine("Warmup...");
        for (int i = 0; i < WARMUP; i++)
        {
#if custom
            using DeterministicSpan<byte> result = sha.ComputeHash(ref buffer);
            //Console.WriteLine(Convert.ToHexString(result.AsSpan()));
#else
            sha.ComputeHash(buffer);
#endif
        }
        Stopwatch stopwatch = new();
        Console.WriteLine("Measuring...");
        stopwatch.Start();
        for (int i = 0; i < ITERATIONS; i++)
        {
#if custom
            using DeterministicSpan<byte> result = sha.ComputeHash(ref buffer);
#else
            sha.ComputeHash(buffer);
#endif
        }
        stopwatch.Stop();
        Console.WriteLine(stopwatch.Elapsed);
        Console.WriteLine($"That's {stopwatch.ElapsedMilliseconds / (double)ITERATIONS} ms / hash");
        Console.WriteLine($"Or {(double)ITERATIONS / stopwatch.ElapsedMilliseconds * 1000} hashes / s");
#if custom
        buffer.Free();
#endif
    }
}

/*

Span.Fill:

00:00:17.3225971
That's 6.9288E-05 ms / hash
Or 14432513.566562753 hashes / s


=======================================

Timing SHA2:

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