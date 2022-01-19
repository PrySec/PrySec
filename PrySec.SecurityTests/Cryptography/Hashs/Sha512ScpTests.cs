using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Security.Cryptography.Hashing.Sha;
using PrySec.SecurityTests;

namespace PrySec.Security.Cryptography.Hashing.Tests;

[TestClass()]
public class Sha512ScpTests : BaseTest
{
    private static readonly Sha512Scp _sha = new();

    [TestMethod()]
    public void Sha512ScpTestVector1()
    {
        const string input = "abc";
        const string expectedHash = "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha512ScpTestVector2()
    {
        string input = string.Empty;
        const string expectedHash = "CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F63B931BD47417A81A538327AF927DA3E";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha512ScpTestVector3()
    {
        const string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        const string expectedHash = "204A8FC6DDA82F0A0CED7BEB8E08A41657C16EF468B228A8279BE331A703C33596FD15C13B1B07F9AA1D3BEA57789CA031AD85C7A71DD70354EC631238CA3445";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha512ScpTestVector4()
    {
        const string input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        const string expectedHash = "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha512ScpTestVector5()
    {
        string input = new('a', 1_000_000);
        const string expectedHash = "E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }

    [TestMethod()]
    public void Sha512ScpTestVector6()
    {
        const string input = "The quick brown fox jumps over the lazy dog";
        const string expectedHash = "07E547D9586F6A73F73FBAC0435ED76951218FB7D0C8D788A309D785436BBB642E93A252A954F23912547D1E8A3B5ED6E1BFD7097821233FA0538F3DB854FEE6";
        Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        AssertMemoryFreed();
    }
}