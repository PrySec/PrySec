using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives.Converters;
using PrySec.CoreTests;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.Metadata;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Core.Primitives.Converters.Tests;

[TestClass]
public class HexConverterTests : BaseTest
{
    [TestMethod]
    public void UnhexlifyTest32_0()
    {
        const string expected = "000102030405060708090A0B0C0D0E0F";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
        string actualString = HexConverter.Hexlify(actualBytes);
        Assert.AreEqual(expected, actualString);
    }

    [TestMethod]
    public void UnhexlifyTest32_1()
    {
        const string expected = "0123456789ABCDEF";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
        string actualString = HexConverter.Hexlify(actualBytes);
        Assert.AreEqual(expected, actualString);
    }

    [TestMethod]
    public void UnhexlifyTest32_2()
    {
        const string expected = "0112233445566778899AABBCCDDEEFF0";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
        string actualString = HexConverter.Hexlify(actualBytes);
        Assert.AreEqual(expected, actualString);
    }
    
    [TestMethod]
    public void HexlifyTest()
    {
        Size_T outputSize = 8192;
        Random random = new(42);
        byte[] bytes = new byte[outputSize];
        random.NextBytes(bytes);

        string expected = Convert.ToHexString(bytes);
        string actual = HexConverter.Hexlify(bytes);

        Assert.AreEqual(expected, actual);
    }

    [TestMethod]
    public void UnhexlifyTest16()
    {
        const string expected = "0001020304050607";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
        string actualString = HexConverter.Hexlify(actualBytes);
        Assert.AreEqual(expected, actualString);
    }

    [TestMethod]
    public void UnhexlifyTest16_2()
    {
        const string expected = "8899AABBCCDDEEFF";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
        string actualString = HexConverter.Hexlify(actualBytes);
        Assert.AreEqual(expected, actualString);
    }

    [TestMethod]
    public void UnhexlifyTest8()
    {
        const string expected = "12345678";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
        string actualString = HexConverter.Hexlify(actualBytes);
        Assert.AreEqual(expected, actualString);
    }

    [TestMethod]
    public void UnhexlifyTest8_2()
    {
        const string expected = "AABBCCDD";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
        string actualString = HexConverter.Hexlify(actualBytes);
        Assert.AreEqual(expected, actualString);
    }

    [TestMethod]
    public void UnhexlifyTest4()
    {
        const string expected = "1234";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
    }

    [TestMethod]
    public void UnhexlifyTest4_2()
    {
        const string input = "aabb";
        const string expected = "AABB";
        byte[] actualBytes = HexConverter.Unhexlify(input);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
    }

    [TestMethod]
    public void UnhexlifyTest2()
    {
        const string expected = "12";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
    }

    [TestMethod]
    public void UnhexlifyTest2_2()
    {
        const string expected = "AA";
        byte[] actualBytes = HexConverter.Unhexlify(expected);
        string actual = Convert.ToHexString(actualBytes);
        Assert.AreEqual(expected, actual);
    }

    [TestMethod]
    public void UnhexlifyTest()
    {
        for (int i = 0; i < 512; i++)
        {
            byte[] bytes = new byte[i];
            Random random = new(42);
            for (int j = 0; j < 64; j++)
            {
                random.NextBytes(bytes);
                string expected = Convert.ToHexString(bytes);
                byte[] actualBytes = HexConverter.Unhexlify(expected);
                string actual = Convert.ToHexString(actualBytes);
                Assert.AreEqual(expected, actual);
            }
        }
    }
}