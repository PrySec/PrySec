using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Blake2;

public unsafe partial class Blake2b
{
    private static class Blake2HwIntrinsicsArm
    {
        public static void HashCore(BlakeCompressionState* state)
        {
        }

        private static void Compress(BlakeCompressionState* state)
        {
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void Mix(ref Vector256<ulong> va, ref Vector256<ulong> vb, ref Vector256<ulong> vc, ref Vector256<ulong> vd, in Vector256<ulong> x, in Vector256<ulong> y)
        {
        }

        // ROTR(x,n) (((x) >> (n)) | ((x) << ((sizeof(x) * 8) - (n))))
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<ulong> RotateRight(Vector256<ulong> vector, byte n) =>
            Avx2.Or(Avx2.ShiftRightLogical(vector, n), Avx2.ShiftLeftLogical(vector, (byte)((sizeof(ulong) << 3) - n)));
    }
}
