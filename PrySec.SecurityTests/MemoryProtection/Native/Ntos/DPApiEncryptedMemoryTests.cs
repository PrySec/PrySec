using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.Memory;
using PrySec.SecurityTests;
using System;
using System.Text;
using System.Linq;

namespace PrySec.Security.MemoryProtection.Native.Ntos.Tests;

#if WIN32

[TestClass]
public unsafe class DPApiEncryptedMemoryTests : BaseTest
{
    private const string TEST_DATA = "this is a test string :P";

    private static DPApiEncryptedMemory<byte> GetTestString(string test)
    {
        Span<byte> bytes = Encoding.ASCII.GetBytes(test).AsSpan();
        return DPApiEncryptedMemory<byte>.CreateFrom(bytes);
    }

    [TestMethod]
    public void Test1()
    {
        using DPApiEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        byte[] rawBytes = Encoding.ASCII.GetBytes(TEST_DATA);
        Span<byte> raw = new(rawBytes);
        Span<byte> encrypted = new(memory.DataPointer, memory.ByteSize);
        Assert.IsFalse(encrypted.SequenceEqual(raw));
    }

    [TestMethod]
    public void Test2()
    {
        byte[] rawBytes = Encoding.ASCII.GetBytes(TEST_DATA);
        Span<byte> raw = new(rawBytes);
        using DPApiEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
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
        using DPApiEncryptedMemory<byte> memory = GetTestString(test);
        Assert.AreEqual(16, (int)memory.ByteSize);
        Assert.AreEqual(16, (int)memory.NativeByteSize);
    }

    [TestMethod]
    public void Test4()
    {
        string test = new('A', 17);
        using DPApiEncryptedMemory<byte> memory = GetTestString(test);
        Assert.AreEqual(17, (int)memory.ByteSize);
        Assert.AreEqual(32, (int)memory.NativeByteSize);
    }

    [TestMethod]
    public void Test5()
    {
        using DPApiEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        using IMemoryAccess<byte> access = memory.GetAccess();
        access.ZeroMemory();
        Span<byte> bytes = access.AsSpan();
        Assert.IsTrue(bytes.ToArray().All(b => b is 0));
    }

    [TestMethod]
    public void Test6()
    {
        DPApiEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        using IMemoryAccess<byte> access = memory.GetAccess();

        // dangerous but should be fine :)
        memory.Dispose();
        Span<byte> bytes = access.AsSpan();
        Assert.IsTrue(bytes.ToArray().All(b => b is 0));
    }

    [TestMethod]
    public void Test7()
    {
        DPApiEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        using IMemoryAccess<byte> access = memory.GetAccess();

        // dangerous but should be fine :)
        memory.Free();
        Span<byte> bytes = access.AsSpan();
        Assert.IsTrue(bytes.ToArray().All(b => b is 0));
    }

    [TestMethod]
    public void Test8()
    {
        using DPApiEncryptedMemory<byte> memory = GetTestString(string.Empty);
        using IMemoryAccess<byte> access = memory.GetAccess();
        Assert.AreEqual(0, (int)memory.ByteSize);
        Assert.AreEqual(0, (int)memory.NativeByteSize);
    }

    [TestMethod]
    public void Test9()
    {
        using DPApiEncryptedMemory<byte> memory = GetTestString(TEST_DATA);
        using (IMemoryAccess<byte> access = memory.GetAccess())
        {
            string test = Encoding.ASCII.GetString(access.AsSpan()[10..14]);
            Assert.AreEqual("test", test);
        }
        using DPApiEncryptedMemory<byte> slice = memory[10..14];
        Assert.AreEqual(4, slice.Count);
        Assert.AreEqual(4, (int)slice.ByteSize);
        Assert.AreEqual(16, (int)slice.NativeByteSize);
        using IMemoryAccess<byte> sliceAccess = slice.GetAccess();
        string alsoTest = Encoding.ASCII.GetString(sliceAccess.AsSpan());
        Assert.AreEqual("test", alsoTest);
    }
}

#endif