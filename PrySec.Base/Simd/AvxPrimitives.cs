using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Runtime.Intrinsics;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Core.Simd;

public static class AvxPrimitives
{
    /// <summary>
    /// MACRO for shuffle parameter for _mm_shuffle_ps(). 
    /// Argument fp3 is a digit[0123] that represents the fp
    /// from argument "b" of mm_shuffle_ps that will be    
    /// placed in fp3 of result. fp2 is the same for fp2 in 
    /// result. fp1 is a digit[0123] that represents the fp 
    /// from argument "a" of mm_shuffle_ps that will be     
    /// places in fp1 of result. fp0 is the same for fp0 of 
    /// result
    /// <para>
    /// <code>
    /// #define _MM_SHUFFLE(fp3,fp2,fp1,fp0) \
    /// (((fp3) &lt;&lt; 6) | ((fp2) &lt;&lt; 4) | ((fp1) &lt;&lt; 2) | ((fp0)))
    /// </code>
    /// </para>
    /// </summary>
#pragma warning disable IDE1006 // Naming Styles
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte _MM_SHUFFLE(int fp3, int fp2, int fp1, int fp0) =>
        (byte)(((fp3) << 6) | ((fp2) << 4) | ((fp1) << 2) | (fp0));
#pragma warning restore IDE1006 // Naming Styles

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static Vector256<ulong> RotateLaneLeft64Bit(Vector256<ulong> input)
    {
        Vector256<double> tmp = Avx.Permute(input.As<ulong, double>(), 0x5);
        
        return Avx.Blend(tmp, Avx.Permute2x128(tmp, tmp, 1), 0xa).As<double, ulong>();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static Vector256<ulong> RotateLaneRight64Bit(Vector256<ulong> input)
    {
        Vector256<double> tmp = Avx.Permute(input.As<ulong, double>(), 0x5);
        return Avx.Blend(tmp, Avx.Permute2x128(tmp, tmp, 1), 0x5).As<double, ulong>();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static Vector256<ulong> Swap128BitLanes(Vector256<ulong> input) => 
        Avx.Permute2x128(input, input, 1);

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static Vector256<ulong> ReverseOrder(Vector256<ulong> input)
    {
        Vector256<double> tmp = Avx.Permute(input.As<ulong, double>(), 0x5);
        return Avx.Permute2x128(tmp, tmp, 1).As<double, ulong>();
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
    public static Vector256<ulong> SwapMiddleX64(Vector256<ulong> input) =>
        Avx2.Permute4x64(input, 0b11011000);
}
