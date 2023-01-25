using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Security.MemoryProtection.Native.Ntos;
using PrySec.Security.MemoryProtection.Portable.XofOtp;
using PrySec.SecurityTests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.MemoryProtection.Portable.XofOtp.Tests;

[TestClass]
public unsafe class Blake3XofOtpEncryptedMemoryTests : BaseTest
{
    private const string TEST_DATA = "this is a test string :P";
    private const string TEST_DATA_2 = "whats the Elvish word for friend";

    static Blake3XofOtpEncryptedMemoryTests()
    {
        // clear any one time static unmanaged allocations
        using (Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(TEST_DATA))
        {
        }
        if (MemoryManager.Allocator is IAllocationTracker tracker)
        {
            tracker.Clear();
        }
    }

    private static Blake3XofOtpEncryptedMemory<byte> GetTestString(string test)
    {
        Span<byte> bytes = Encoding.ASCII.GetBytes(test).AsSpan();
        return Blake3XofOtpEncryptedMemory<byte>.CreateFrom(bytes);
    }

    [TestMethod]
    public void Test1()
    {
        using Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        byte[] rawBytes = Encoding.ASCII.GetBytes(TEST_DATA);
        Span<byte> raw = new(rawBytes);
        Span<byte> encrypted = new(memory.DataPointer, memory.ByteSize);
        Assert.IsFalse(encrypted.SequenceEqual(raw));
        string s = Encoding.ASCII.GetString(encrypted);
    }

    [TestMethod]
    public void Test2()
    {
        byte[] rawBytes = Encoding.ASCII.GetBytes(TEST_DATA);
        Span<byte> raw = new(rawBytes);
        using Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        Assert.AreEqual(rawBytes.Length, (int)memory.ByteSize);
        Assert.AreEqual(rawBytes.Length, memory.Count);
        using IMemoryAccess<byte> access = memory.GetAccess();
        Span<byte> decrypted = access.AsSpan();
        Assert.IsTrue(decrypted.SequenceEqual(raw));
    }

    [TestMethod]
    public void Test3()
    {
        string test = new('A', 16);
        using Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(test);
        Assert.AreEqual(16, (int)memory.ByteSize);
        Assert.AreEqual(16 + Blake3XofOtpEncryptedMemory<byte>.IVSize, (int)memory.NativeByteSize);
    }

    [TestMethod]
    public void Test4()
    {
        string test = new('A', 17);
        using Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(test);
        Assert.AreEqual(17, (int)memory.ByteSize);
        Assert.AreEqual(17 + Blake3XofOtpEncryptedMemory<byte>.IVSize, (int)memory.NativeByteSize);
    }

    [TestMethod]
    public void Test5()
    {
        using Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        using IMemoryAccess<byte> access = memory.GetAccess();
        access.ZeroMemory();
        Span<byte> bytes = access.AsSpan();
        Assert.IsTrue(bytes.ToArray().All(b => b is 0));
    }

    [TestMethod]
    public void Test6()
    {
        Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        using IMemoryAccess<byte> access = memory.GetAccess();

        // dangerous but should be fine :)
        memory.Dispose();
        Span<byte> bytes = access.AsSpan();
        Assert.IsTrue(bytes.ToArray().All(b => b is 0));
    }

    [TestMethod]
    public void Test7()
    {
        Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        using IMemoryAccess<byte> access = memory.GetAccess();

        // dangerous but should be fine :)
        memory.Free();
        Span<byte> bytes = access.AsSpan();
        Assert.IsTrue(bytes.ToArray().All(b => b is 0));
    }

    [TestMethod]
    public void Test8()
    {
        using Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(string.Empty);
        using IMemoryAccess<byte> access = memory.GetAccess();
        Assert.AreEqual(0, (int)memory.ByteSize);
        Assert.AreEqual(0, (int)memory.NativeByteSize);
    }

    [TestMethod]
    public void Test9()
    {
        using Blake3XofOtpEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        using (IMemoryAccess<byte> access = memory.GetAccess())
        {
            string test = Encoding.ASCII.GetString(access.AsSpan()[10..14]);
            Assert.AreEqual("test", test);
        }
        using Blake3XofOtpEncryptedMemory<byte> slice = memory[10..14];
        Assert.AreEqual(4, slice.Count);
        Assert.AreEqual(4, (int)slice.ByteSize);
        Assert.AreEqual(4 + Blake3XofOtpEncryptedMemory<byte>.IVSize, (int)slice.NativeByteSize);
        using IMemoryAccess<byte> sliceAccess = slice.GetAccess();
        string alsoTest = Encoding.ASCII.GetString(sliceAccess.AsSpan());
        Assert.AreEqual("test", alsoTest);
    }
}