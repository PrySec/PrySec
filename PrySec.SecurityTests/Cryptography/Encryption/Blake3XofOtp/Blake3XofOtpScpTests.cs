using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Security.Cryptography.Csprng;
using PrySec.Security.Cryptography.Encryption.Blake3XofOtp;
using PrySec.Security.MemoryProtection.Portable;
using PrySec.SecurityTests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Encryption.Blake3XofOtp.Tests;

[TestClass]
public unsafe class Blake3XofOtpScpTests : BaseTest
{
    private static readonly Blake3XofOtpScp _otp;

    static Blake3XofOtpScpTests()
    {
        _otp = new("https://github.com/frederik-hoeft/PrySec 2023-01-25 22:47:27 Blake3XofOtpScpTests");
        if (MemoryManager.Allocator is IAllocationTracker tracker)
        {
            tracker.Clear();
        }
    }

    [TestMethod]
    public void ComputeInlineTest1()
    {
        Span<byte> bytes = stackalloc byte[64];
        bytes.Fill(0xff);
        DeterministicMemory<byte> key = DeterministicMemory<byte>.CreateFrom(bytes);
        byte* target = stackalloc byte[255];
        Span<byte> t = new(target, 255);
        t.Clear();
        _otp.ComputeInline(ref key, target, 255);
        Assert.IsTrue(t.ToArray().Any(b => b != 0));
        _otp.ComputeInline(ref key, target, 255);
        Assert.IsTrue(t.ToArray().All(b => b == 0));
        key.Dispose();
    }

    [TestMethod]
    public void ComputeInlineTest2()
    {
        Span<byte> bytes = stackalloc byte[64];
        bytes.Fill(0xff);
        DeterministicMemory<byte> key = DeterministicMemory<byte>.CreateFrom(bytes);
        byte* target = stackalloc byte[255];
        Span<byte> t = new(target, 255);
        Span<byte> original = stackalloc byte[255];
        SecureRandom.Fill(t);
        t.CopyTo(original);
        _otp.ComputeInline(ref key, target, 255);
        Assert.IsFalse(t.SequenceEqual(original));
        _otp.ComputeInline(ref key, target, 255);
        Assert.IsTrue(t.SequenceEqual(original));
        key.Dispose();
    }
}