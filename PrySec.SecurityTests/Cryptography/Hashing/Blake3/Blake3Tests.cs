using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Security.MemoryProtection.Portable;
using PrySec.SecurityTests;
using System;

namespace PrySec.Security.Cryptography.Hashing.Blake3.Tests;

[TestClass]
public class Blake3Tests : BaseTest
{
    private static readonly Blake3 _blake;

    const string context = "BLAKE3 2019-12-27 16:29:52 test vectors context";
    const string key = "whats the Elvish word for friend";
    const int outputLength = 131;

    static Blake3Tests()
    {
        _blake = new Blake3();

        if (MemoryManager.Allocator is IAllocationTracker tracker)
        {
            tracker.Clear();
        }
    }

    [TestMethod]
    public void ComputeHashTest1()
    {
        string input = string.Empty;
        const string expectedHash = "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));
    }

    [TestMethod]
    public void ComputeHashTest2()
    {
        const string input = "asdf";
        const string expectedHash = "9E70EE1449965FB62D049040A1ED06EC377430DA6EC13173E7C4FFFCD28BE980";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));
    }

    [TestMethod]
    public void ComputeHashTest3()
    {
        string input = new('A', 4096);
        const string expectedHash = "4598E001CD6E4C4FE4AA57BB055C11F1CBE10B3E0DEF42DE0DA8EC4036500F6C";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));
    }

    [TestMethod]
    public void ComputeHashTest4()
    {
        string input = new('A', 100_000);
        const string expectedHash = "AC0322EE66C770A7342777BE95BA8FEAE791AFC681F100E430732DD8D37B0E5B";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));
    }

    [TestMethod]
    public unsafe void ComputeHashTest5()
    {
        DeterministicMemory<byte> input = GenerateInput(0);
        const string expectedHash = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d";
        using DeterministicMemory<byte> output = _blake.ComputeHash<byte, DeterministicMemory<byte>, DeterministicMemory<byte>>(ref input, outputLength);
        string hash = Convert.ToHexString(new Span<byte>(output.BasePointer, output.ByteSize));
        Assert.AreEqual(expectedHash, hash.ToLower());
        input.Dispose();
    }

    [TestMethod]
    public unsafe void ComputeHashTest6()
    {
        DeterministicMemory<byte> input = GenerateInput(102400);
        const string expectedHash = "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204f45f8e";
        using DeterministicMemory<byte> output = _blake.ComputeHash<byte, DeterministicMemory<byte>, DeterministicMemory<byte>>(ref input, outputLength);
        string hash = Convert.ToHexString(new Span<byte>(output.BasePointer, output.ByteSize));
        Assert.AreEqual(expectedHash, hash.ToLower());
        input.Dispose();
    }

    [TestMethod]
    public unsafe void DeriveKeyTest1()
    {
        DeterministicMemory<byte> input = GenerateInput(0);
        const string expectedHash = "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfcf3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4a3f746752c6b0ce6a83b0da81d59649257cdf8eb3e9f7d4998e41021fac119deefb896224ac99f860011f73609e6e0e4540f93b273e56547dfd3aa1a035ba6689d89a0";
        using DeterministicMemory<byte> output = _blake.DeriveKey<byte, DeterministicMemory<byte>, DeterministicMemory<byte>>(ref input, context, outputLength);
        string hash = Convert.ToHexString(new Span<byte>(output.BasePointer, output.ByteSize));
        Assert.AreEqual(expectedHash, hash.ToLower());
        input.Dispose();
    }

    [TestMethod]
    public unsafe void DeriveKeyTest2()
    {
        DeterministicMemory<byte> input = GenerateInput(102400);
        const string expectedHash = "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6d83a3e041bc3a48df2879f4a0a3ed40e7c961c73eff740f3117a0504c2dff4786d44fb17f1549eb0ba585e40ec29bf7732f0b7e286ff8acddc4cb1e23b87ff5d824a986458dcc6a04ac83969b80637562953df51ed1a7e90a7926924d2763778be8560";
        using DeterministicMemory<byte> output = _blake.DeriveKey<byte, DeterministicMemory<byte>, DeterministicMemory<byte>>(ref input, context, outputLength);
        string hash = Convert.ToHexString(new Span<byte>(output.BasePointer, output.ByteSize));
        Assert.AreEqual(expectedHash, hash.ToLower());
        input.Dispose();
    }

    private static unsafe DeterministicMemory<byte> GenerateInput(int length)
    {
        DeterministicMemory<byte> input = DeterministicMemory<byte>.Allocate(length);
        for (int i = 0; i < length; )
        {
            for (int j = 0; j < 251 && i < length; j++, i++)
            {
                input.BasePointer[i] = (byte)j;
            }
        }
        return input;
    }
}
