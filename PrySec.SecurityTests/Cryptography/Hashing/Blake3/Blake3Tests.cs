using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Security.Cryptography.Hashing;
using PrySec.Security.Cryptography.Hashing.Blake3;
using PrySec.Security.Cryptography.Hashing.Sha;
using PrySec.SecurityTests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Blake3.Tests;

[TestClass()]
public class Blake3Tests : BaseTest
{
    private static readonly Blake3 _blake;

    static Blake3Tests()
    {
        _blake = new Blake3();
        MemoryManager.GetAllocationSnapshot(true);
    }

    [TestMethod()]
    public void ComputeHashTest1()
    {
        string input = string.Empty;
        const string expectedHash = "AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));

        AssertMemoryFreed();
    }

    [TestMethod()]
    public void ComputeHashTest2()
    {
        const string input = "asdf";
        const string expectedHash = "9E70EE1449965FB62D049040A1ED06EC377430DA6EC13173E7C4FFFCD28BE980";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));

        AssertMemoryFreed();
    }

    [TestMethod()]
    public void ComputeHashTest3()
    {
        string input = new('A', 4096);
        const string expectedHash = "4598E001CD6E4C4FE4AA57BB055C11F1CBE10B3E0DEF42DE0DA8EC4036500F6C";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));

        AssertMemoryFreed();
    }

    [TestMethod()]
    public void ComputeHashTest4()
    {
        string input = new('A', 100_000);
        const string expectedHash = "AC0322EE66C770A7342777BE95BA8FEAE791AFC681F100E430732DD8D37B0E5B";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));

        AssertMemoryFreed();
    }

    [TestCleanup]
    public void Cleanup() => MemoryManager.GetAllocationSnapshot(true);
}
