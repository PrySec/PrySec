using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Security.Cryptography.Hashing.Sha;
using PrySec.SecurityTests;
using System.Runtime.Versioning;

namespace PrySec.Security.Cryptography.Hashing.Tests;

[TestClass()]
[RequiresPreviewFeatures]
public class Sha256ScpTests : BaseTest
{
    private static readonly Sha256Scp _sha = new();

    [TestMethod()]
    public void Sha256ScpTestVector1()
    {
        const string input = "abc";
        const string expectedHash = "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha256ScpTestVector2()
    {
        string input = string.Empty;
        const string expectedHash = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha256ScpTestVector3()
    {
        const string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        const string expectedHash = "248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha256ScpTestVector4()
    {
        const string input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        const string expectedHash = "CF5B16A778AF8380036CE59E7B0492370B249B11E8F07A51AFAC45037AFEE9D1";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha256ScpTestVector5()
    {
        string input = new('a', 1_000_000);
        const string expectedHash = "CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha256ScpTestVector6()
    {
        const string input = "The quick brown fox jumps over the lazy dog";
        const string expectedHash = "D7A8FBB307D7809469CA9ABCB0082E4F8D5651E46D3CDB762D02D0BF37C9E592";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }
}