using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Base.Memory;
using PrySec.Security.Cryptography.Hashing.Sha;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Tests
{
    [TestClass()]
    public class Sha1ScpTests
    {
        private static readonly Sha1Scp _sha = new();

        [TestMethod()]
        public void Sha1ScpTestVector1()
        {
            const string input = "abc";
            const string expectedHash = "A9993E364706816ABA3E25717850C26C9CD0D89D";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }

        [TestMethod()]
        public void Sha1ScpTestVector2()
        {
            string input = string.Empty;
            const string expectedHash = "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }

        [TestMethod()]
        public void Sha1ScpTestVector3()
        {
            const string input = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
            const string expectedHash = "84983E441C3BD26EBAAE4AA1F95129E5E54670F1";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }

        [TestMethod()]
        public void Sha1ScpTestVector4()
        {
            const string input = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
            const string expectedHash = "A49B2446A02C645BF419F995B67091253A04A259";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }

        [TestMethod()]
        public void Sha1ScpTestVector5()
        {
            string input = new('a', 1_000_000);
            const string expectedHash = "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }


        [TestMethod()]
        public void Sha1ScpTestVector6()
        {
            const string input = "The quick brown fox jumps over the lazy dog";
            const string expectedHash = "2FD4E1C67A2D28FCED849EE1BB76E7391B93EB12";
            Assert.AreEqual(expectedHash, _sha.ComputeHash(input));
        }
    }
}