using PrySec.Core.NativeTypes;
using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Core.HwPrimitives;

[DebuggerStepThrough]
public static unsafe class BinaryDebugUtils
{
    [Conditional("DEBUG")]
    public static void DebugPrint<T>(this Vector256<T> v) where T : struct =>
        Debug.WriteLine(v.AsByte());

    [Conditional("DEBUG")]
    public static void DebugPrint<T>(this Vector128<T> v) where T : struct =>
        Debug.WriteLine(v.AsByte());
}