using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Security.Cryptography.Hashing.Blake2;
using PrySec.Security.Cryptography.Hashing.Sha;
using PrySec.SecurityTests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Blake2.Tests;

[TestClass()]
public class Blake2bTests : BaseTest
{
    private static readonly Blake2b _blake;

    static Blake2bTests()
    {
        _blake = new Blake2b();
        MemoryManager.GetAllocationSnapshot(true);
    }

    [TestMethod()]
    public void ComputeHashTest1()
    {
        string input = string.Empty;
        const string expectedHash = "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));

        AssertMemoryFreed();
    }

    [TestMethod()]
    public void ComputeHashTest2()
    {
        string input = "The quick brown fox jumps over the lazy dog";
        const string expectedHash = "A8ADD4BDDDFD93E4877D2746E62817B116364A1FA7BC148D95090BC7333B3673F82401CF7AA2E4CB1ECD90296E3F14CB5413F8ED77BE73045B13914CDCD6A918";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));

        AssertMemoryFreed();
    }

    [TestMethod()]
    public void ComputeHashTest3()
    {
        string input = "The quick brown fox jumps over the lazy dof";
        const string expectedHash = "AB6B007747D8068C02E25A6008DB8A77C218D94F3B40D2291A7DC8A62090A744C082EA27AF01521A102E42F480A31E9844053F456B4B41E8AA78BBE5C12957BB";
        Assert.AreEqual(expectedHash, _blake.ComputeHash(input));

        AssertMemoryFreed();
    }


    [TestCleanup]
    public void Cleanup() => MemoryManager.GetAllocationSnapshot(true);
}
