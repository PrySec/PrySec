using System.Diagnostics;

namespace PrySec.Core;

[DebuggerStepThrough]
public static unsafe class FastMath
{
    /// <summary>
    /// Calculates the minimum of <paramref name="x"/> and <paramref name="y"/> where <c>int.MinValue <= x - y <= int.MaxValue</c>
    /// <param name="x">x</param>
    /// <param name="y">y</param>
    /// </summary>
    public static int Min(int x, int y) => 
        y + ((x - y) & ((x - y) >> 31));
    /// <summary>
    /// Calculates the maximum of <paramref name="x"/> and <paramref name="y"/> where <c>int.MinValue <= x - y <= int.MaxValue</c>
    /// </summary>
    /// <param name="x">x</param>
    /// <param name="y">y</param>
    /// <returns></returns>
    public static int Max(int x, int y) =>
        x - ((x - y) & ((x - y) >> 31));
}
