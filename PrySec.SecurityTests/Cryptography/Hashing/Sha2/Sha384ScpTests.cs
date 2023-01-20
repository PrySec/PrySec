using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Security.Cryptography.Hashing;
using PrySec.Security.Cryptography.Hashing.Sha;
using PrySec.SecurityTests;
using System.Runtime.Versioning;

namespace PrySec.SecurityTests.Cryptography.Hashing.Sha2;

[TestClass]
public class Sha384ScpTests : BaseTest
{
    private static readonly Sha384Scp _sha = new();

    [TestMethod]
    public void Sha384ScpTestVector1()
    {
        const string input = "abc";
        const string expectedHash = "CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED1631A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
    }

    [TestMethod]
    public void Sha384ScpTestVector2()
    {
        string input = string.Empty;
        const string expectedHash = "38B060A751AC96384CD9327EB1B1E36A21FDB71114BE07434C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
    }

    [TestMethod]
    public void Sha384ScpTestVector3()
    {
        const string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        const string expectedHash = "3391FDDDFC8DC7393707A65B1B4709397CF8B1D162AF05ABFE8F450DE5F36BC6B0455A8520BC4E6F5FE95B1FE3C8452B";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
    }

    [TestMethod]
    public void Sha384ScpTestVector4()
    {
        const string input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        const string expectedHash = "09330C33F71147E83D192FC782CD1B4753111B173B3B05D22FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
    }

    [TestMethod]
    public void Sha384ScpTestVector5()
    {
        string input = new('a', 1_000_000);
        const string expectedHash = "9D0E1809716474CB086E834E310A4A1CED149E9C00F248527972CEC5704C2A5B07B8B3DC38ECC4EBAE97DDD87F3D8985";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
    }

    [TestMethod]
    public void Sha384ScpTestVector6()
    {
        const string input = "The quick brown fox jumps over the lazy dog";
        const string expectedHash = "CA737F1014A48F4C0B6DD43CB177B0AFD9E5169367544C494011E3317DBF9A509CB1E5DC1E85A941BBEE3D7F2AFBC9B1";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
    }
}