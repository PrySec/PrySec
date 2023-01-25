using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.HwPrimitives;
using System.Runtime.Intrinsics;

namespace PrySec.Core.Simd.Tests;

[TestClass()]
public class AvxPrimitivesTests
{
    [TestMethod()]
    public void RotateLaneLeft64BitTest1()
    {
        Vector256<ulong> input = Vector256.Create(0ul, 1ul, 2ul, 3ul);
        Vector256<ulong> expected = Vector256.Create(1ul, 2ul, 3ul, 0ul);
        Vector256<ulong> actual = AvxPrimitives.RotateLaneLeft64Bit(input);

        Assert.AreEqual(expected, actual);
    }

    [TestMethod()]
    public void RotateLaneLeft64BitTest2()
    {
        Vector256<ulong> input = Vector256.Create(0ul, 3ul, 7ul, 10ul);
        Vector256<ulong> expected = Vector256.Create(3ul, 7ul, 10ul, 0ul);
        Vector256<ulong> actual = AvxPrimitives.RotateLaneLeft64Bit(input);

        Assert.AreEqual(expected, actual);
    }

    [TestMethod()]
    public void RotateLaneRight64BitTest1()
    {
        Vector256<ulong> input = Vector256.Create(0ul, 1ul, 2ul, 3ul);
        Vector256<ulong> expected = Vector256.Create(3ul, 0ul, 1ul, 2ul);
        Vector256<ulong> actual = AvxPrimitives.RotateLaneRight64Bit(input);

        Assert.AreEqual(expected, actual);
    }
    
    [TestMethod()]
    public void RotateLaneRight64BitTest2()
    {
        Vector256<ulong> input = Vector256.Create(0ul, 3ul, 7ul, 10ul);
        Vector256<ulong> expected = Vector256.Create(10ul, 0ul, 3ul, 7ul);
        Vector256<ulong> actual = AvxPrimitives.RotateLaneRight64Bit(input);

        Assert.AreEqual(expected, actual);
    }

    [TestMethod()]
    public void Swap128BitLanesTest1()
    {
        Vector256<ulong> input = Vector256.Create(0ul, 1ul, 2ul, 3ul);
        Vector256<ulong> expected = Vector256.Create(2ul, 3ul, 0ul, 1ul);
        Vector256<ulong> actual = AvxPrimitives.Swap128BitLanes(input);

        Assert.AreEqual(expected, actual);
    }

    [TestMethod()]
    public void Swap128BitLanesTest2()
    {
        Vector256<ulong> input = Vector256.Create(0ul, 3ul, 7ul, 10ul);
        Vector256<ulong> expected = Vector256.Create(7ul, 10ul, 0ul, 3ul);
        Vector256<ulong> actual = AvxPrimitives.Swap128BitLanes(input);

        Assert.AreEqual(expected, actual);
    }
}
