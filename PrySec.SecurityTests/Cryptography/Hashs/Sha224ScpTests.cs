using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Security.Cryptography.Hashing.Sha;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Tests
{
    [TestClass()]
    public class Sha224ScpTests
    {
        private static readonly Sha224Scp _sha = new();

        [TestMethod()]
        public void Sha224ScpTestVector1()
        {
            const string input = "abc";
            const string expectedHash = "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }

        [TestMethod()]
        public void Sha224ScpTestVector2()
        {
            string input = string.Empty;
            const string expectedHash = "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }

        [TestMethod()]
        public void Sha224ScpTestVector3()
        {
            const string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
            const string expectedHash = "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }

        [TestMethod()]
        public void Sha224ScpTestVector4()
        {
            const string input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
            const string expectedHash = "C97CA9A559850CE97A04A96DEF6D99A9E0E0E2AB14E6B8DF265FC0B3";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }

        [TestMethod()]
        public void Sha224ScpTestVector5()
        {
            string input = new('a', 1_000_000);
            const string expectedHash = "20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }


        [TestMethod()]
        public void Sha224ScpTestVector6()
        {
            const string input = "The quick brown fox jumps over the lazy dog";
            const string expectedHash = "730E109BD7A8A32B1CB9D9A09AA2325D2430587DDBC0C38BAD911525";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }
    }
}