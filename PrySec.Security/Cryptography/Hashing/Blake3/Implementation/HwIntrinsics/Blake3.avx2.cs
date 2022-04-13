﻿using PrySec.Core.HwPrimitives;
using PrySec.Core.NativeTypes;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Hashing.Blake3;

public unsafe partial class Blake3
{
    private class Blake3HwIntrinsicsAvx2 : IBlake3Implementation
    {
        public static int SimdDegree => 8;

        public static void CompressInPlace(uint* cv, byte* block, byte blockLength, ulong counter, Blake3Flags flags)
        {
            
        }
        
        public static void CompressXof(uint* cv, byte* block, byte blockLength, ulong counter, Blake3Flags flags, byte* output)
        {
            
        }
        
        public static void HashMany(byte** inputs, Size64_T inputCount, Size_T blockCount, uint* key, ulong counter, bool incrementCounter, Blake3Flags flags, Blake3Flags flagsStart, Blake3Flags flagsEnd, byte* output)
        {
            
        }

        #region private methods
        
        private static readonly Vector256<byte> _rot8Data;
        private static readonly Vector256<byte> _rot16Data;

        static Blake3HwIntrinsicsAvx2()
        {
            ulong* buf = stackalloc ulong[4];
            BinaryUtils.WriteUInt64BigEndian(buf + 0, 0x0C0F0E0D080B0A09uL);
            BinaryUtils.WriteUInt64BigEndian(buf + 1, 0x0407060500030201uL);
            BinaryUtils.WriteUInt64BigEndian(buf + 2, 0x0C0F0E0D080B0A09uL);
            BinaryUtils.WriteUInt64BigEndian(buf + 3, 0x0407060500030201uL);
            _rot8Data = Avx.LoadVector256((byte*)buf);
            
            BinaryUtils.WriteUInt64BigEndian(buf + 0, 0x0D0C0F0E09080B0AuL);
            BinaryUtils.WriteUInt64BigEndian(buf + 1, 0x0504070601000302uL);
            BinaryUtils.WriteUInt64BigEndian(buf + 2, 0x0D0C0F0E09080B0AuL);
            BinaryUtils.WriteUInt64BigEndian(buf + 3, 0x0504070601000302uL);
            _rot16Data = Avx.LoadVector256((byte*)buf);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<uint> Rot16(Vector256<uint> x) => 
            Avx2.Shuffle(x.As<uint, byte>(), _rot16Data).As<byte, uint>();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<uint> Rot12(Vector256<uint> x) => 
            Avx2.Or(Avx2.ShiftRightLogical(x, 12), Avx2.ShiftLeftLogical(x, 32 - 12));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<uint> Rot8(Vector256<uint> x) =>
            Avx2.Shuffle(x.As<uint, byte>(), _rot8Data).As<byte, uint>();

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector256<uint> Rot7(Vector256<uint> x) =>
            Avx2.Or(Avx2.ShiftRightLogical(x, 7), Avx2.ShiftLeftLogical(x, 32 - 7));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void RoundFunction(Vector256<uint>* v, Vector256<uint>* m, Size_T r)
        {
            v[0] = Avx2.Add(v[0], m[MSG_SCHEDULE[r, 0]]);
            v[1] = Avx2.Add(v[1], m[MSG_SCHEDULE[r, 2]]);
            v[2] = Avx2.Add(v[2], m[MSG_SCHEDULE[r, 4]]);
            v[3] = Avx2.Add(v[3], m[MSG_SCHEDULE[r, 6]]);
            v[0] = Avx2.Add(v[0], v[4]);
            v[1] = Avx2.Add(v[1], v[5]);
            v[2] = Avx2.Add(v[2], v[6]);
            v[3] = Avx2.Add(v[3], v[7]);
            v[12] = Avx2.Xor(v[12], v[0]);
            v[13] = Avx2.Xor(v[13], v[1]);
            v[14] = Avx2.Xor(v[14], v[2]);
            v[15] = Avx2.Xor(v[15], v[3]);
            v[12] = Rot16(v[12]);
            v[13] = Rot16(v[13]);
            v[14] = Rot16(v[14]);
            v[15] = Rot16(v[15]);
            v[8] = Avx2.Add(v[8], v[12]);
            v[9] = Avx2.Add(v[9], v[13]);
            v[10] = Avx2.Add(v[10], v[14]);
            v[11] = Avx2.Add(v[11], v[15]);
            v[4] = Avx2.Xor(v[4], v[8]);
            v[5] = Avx2.Xor(v[5], v[9]);
            v[6] = Avx2.Xor(v[6], v[10]);
            v[7] = Avx2.Xor(v[7], v[11]);
            v[4] = Rot12(v[4]);
            v[5] = Rot12(v[5]);
            v[6] = Rot12(v[6]);
            v[7] = Rot12(v[7]);
            v[0] = Avx2.Add(v[0], m[MSG_SCHEDULE[r, 1]]);
            v[1] = Avx2.Add(v[1], m[MSG_SCHEDULE[r, 3]]);
            v[2] = Avx2.Add(v[2], m[MSG_SCHEDULE[r, 5]]);
            v[3] = Avx2.Add(v[3], m[MSG_SCHEDULE[r, 7]]);
            v[0] = Avx2.Add(v[0], v[4]);
            v[1] = Avx2.Add(v[1], v[5]);
            v[2] = Avx2.Add(v[2], v[6]);
            v[3] = Avx2.Add(v[3], v[7]);
            v[12] = Avx2.Xor(v[12], v[0]);
            v[13] = Avx2.Xor(v[13], v[1]);
            v[14] = Avx2.Xor(v[14], v[2]);
            v[15] = Avx2.Xor(v[15], v[3]);
            v[12] = Rot8(v[12]);
            v[13] = Rot8(v[13]);
            v[14] = Rot8(v[14]);
            v[15] = Rot8(v[15]);
            v[8] = Avx2.Add(v[8], v[12]);
            v[9] = Avx2.Add(v[9], v[13]);
            v[10] = Avx2.Add(v[10], v[14]);
            v[11] = Avx2.Add(v[11], v[15]);
            v[4] = Avx2.Xor(v[4], v[8]);
            v[5] = Avx2.Xor(v[5], v[9]);
            v[6] = Avx2.Xor(v[6], v[10]);
            v[7] = Avx2.Xor(v[7], v[11]);
            v[4] = Rot7(v[4]);
            v[5] = Rot7(v[5]);
            v[6] = Rot7(v[6]);
            v[7] = Rot7(v[7]);

            v[0] = Avx2.Add(v[0], m[MSG_SCHEDULE[r, 8]]);
            v[1] = Avx2.Add(v[1], m[MSG_SCHEDULE[r, 10]]);
            v[2] = Avx2.Add(v[2], m[MSG_SCHEDULE[r, 12]]);
            v[3] = Avx2.Add(v[3], m[MSG_SCHEDULE[r, 14]]);
            v[0] = Avx2.Add(v[0], v[5]);
            v[1] = Avx2.Add(v[1], v[6]);
            v[2] = Avx2.Add(v[2], v[7]);
            v[3] = Avx2.Add(v[3], v[4]);
            v[15] = Avx2.Xor(v[15], v[0]);
            v[12] = Avx2.Xor(v[12], v[1]);
            v[13] = Avx2.Xor(v[13], v[2]);
            v[14] = Avx2.Xor(v[14], v[3]);
            v[15] = Rot16(v[15]);
            v[12] = Rot16(v[12]);
            v[13] = Rot16(v[13]);
            v[14] = Rot16(v[14]);
            v[10] = Avx2.Add(v[10], v[15]);
            v[11] = Avx2.Add(v[11], v[12]);
            v[8] = Avx2.Add(v[8], v[13]);
            v[9] = Avx2.Add(v[9], v[14]);
            v[5] = Avx2.Xor(v[5], v[10]);
            v[6] = Avx2.Xor(v[6], v[11]);
            v[7] = Avx2.Xor(v[7], v[8]);
            v[4] = Avx2.Xor(v[4], v[9]);
            v[5] = Rot12(v[5]);
            v[6] = Rot12(v[6]);
            v[7] = Rot12(v[7]);
            v[4] = Rot12(v[4]);
            v[0] = Avx2.Add(v[0], m[MSG_SCHEDULE[r, 9]]);
            v[1] = Avx2.Add(v[1], m[MSG_SCHEDULE[r, 11]]);
            v[2] = Avx2.Add(v[2], m[MSG_SCHEDULE[r, 13]]);
            v[3] = Avx2.Add(v[3], m[MSG_SCHEDULE[r, 15]]);
            v[0] = Avx2.Add(v[0], v[5]);
            v[1] = Avx2.Add(v[1], v[6]);
            v[2] = Avx2.Add(v[2], v[7]);
            v[3] = Avx2.Add(v[3], v[4]);
            v[15] = Avx2.Xor(v[15], v[0]);
            v[12] = Avx2.Xor(v[12], v[1]);
            v[13] = Avx2.Xor(v[13], v[2]);
            v[14] = Avx2.Xor(v[14], v[3]);
            v[15] = Rot8(v[15]);
            v[12] = Rot8(v[12]);
            v[13] = Rot8(v[13]);
            v[14] = Rot8(v[14]);
            v[10] = Avx2.Add(v[10], v[15]);
            v[11] = Avx2.Add(v[11], v[12]);
            v[8] = Avx2.Add(v[8], v[13]);
            v[9] = Avx2.Add(v[9], v[14]);
            v[5] = Avx2.Xor(v[5], v[10]);
            v[6] = Avx2.Xor(v[6], v[11]);
            v[7] = Avx2.Xor(v[7], v[8]);
            v[4] = Avx2.Xor(v[4], v[9]);
            v[5] = Rot7(v[5]);
            v[6] = Rot7(v[6]);
            v[7] = Rot7(v[7]);
            v[4] = Rot7(v[4]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void TransposeVectors(Vector256<uint>* vecs)
        {
            // Interleave 32-bit lanes. The low unpack is lanes 00/11/44/55, and the high
            // is 22/33/66/77.
            Vector256<ulong> ab_0145 = Avx2.UnpackLow(vecs[0], vecs[1]).As<uint, ulong>();
            Vector256<ulong> ab_2367 = Avx2.UnpackHigh(vecs[0], vecs[1]).As<uint, ulong>();
            Vector256<ulong> cd_0145 = Avx2.UnpackLow(vecs[2], vecs[3]).As<uint, ulong>();
            Vector256<ulong> cd_2367 = Avx2.UnpackHigh(vecs[2], vecs[3]).As<uint, ulong>();
            Vector256<ulong> ef_0145 = Avx2.UnpackLow(vecs[4], vecs[5]).As<uint, ulong>();
            Vector256<ulong> ef_2367 = Avx2.UnpackHigh(vecs[4], vecs[5]).As<uint, ulong>();
            Vector256<ulong> gh_0145 = Avx2.UnpackLow(vecs[6], vecs[7]).As<uint, ulong>();
            Vector256<ulong> gh_2367 = Avx2.UnpackHigh(vecs[6], vecs[7]).As<uint, ulong>();

            // Interleave 64-bit lates. The low unpack is lanes 00/22 and the high is
            // 11/33.
            Vector256<ulong> abcd_04 = Avx2.UnpackLow(ab_0145, cd_0145);
            Vector256<ulong> abcd_15 = Avx2.UnpackHigh(ab_0145, cd_0145);
            Vector256<ulong> abcd_26 = Avx2.UnpackLow(ab_2367, cd_2367);
            Vector256<ulong> abcd_37 = Avx2.UnpackHigh(ab_2367, cd_2367);
            Vector256<ulong> efgh_04 = Avx2.UnpackLow(ef_0145, gh_0145);
            Vector256<ulong> efgh_15 = Avx2.UnpackHigh(ef_0145, gh_0145);
            Vector256<ulong> efgh_26 = Avx2.UnpackLow(ef_2367, gh_2367);
            Vector256<ulong> efgh_37 = Avx2.UnpackHigh(ef_2367, gh_2367);

            // Interleave 128-bit lanes.
            vecs[0] = Avx2.Permute2x128(abcd_04, efgh_04, 0x20).As<ulong, uint>();
            vecs[1] = Avx2.Permute2x128(abcd_15, efgh_15, 0x20).As<ulong, uint>();
            vecs[2] = Avx2.Permute2x128(abcd_26, efgh_26, 0x20).As<ulong, uint>();
            vecs[3] = Avx2.Permute2x128(abcd_37, efgh_37, 0x20).As<ulong, uint>();
            vecs[4] = Avx2.Permute2x128(abcd_04, efgh_04, 0x31).As<ulong, uint>();
            vecs[5] = Avx2.Permute2x128(abcd_15, efgh_15, 0x31).As<ulong, uint>();
            vecs[6] = Avx2.Permute2x128(abcd_26, efgh_26, 0x31).As<ulong, uint>();
            vecs[7] = Avx2.Permute2x128(abcd_37, efgh_37, 0x31).As<ulong, uint>();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void TransposeMessageVectors(byte** inputs, Size_T blockOffset, Vector256<uint>* output)
        {
            const int VECTOR_SIZE = 8 * sizeof(uint);
            output[0] = Avx.LoadVector256((uint*)(inputs[0] + blockOffset + 0 * VECTOR_SIZE));
            output[1] = Avx.LoadVector256((uint*)(inputs[1] + blockOffset + 0 * VECTOR_SIZE));
            output[2] = Avx.LoadVector256((uint*)(inputs[2] + blockOffset + 0 * VECTOR_SIZE));
            output[3] = Avx.LoadVector256((uint*)(inputs[3] + blockOffset + 0 * VECTOR_SIZE));
            output[4] = Avx.LoadVector256((uint*)(inputs[4] + blockOffset + 0 * VECTOR_SIZE));
            output[5] = Avx.LoadVector256((uint*)(inputs[5] + blockOffset + 0 * VECTOR_SIZE));
            output[6] = Avx.LoadVector256((uint*)(inputs[6] + blockOffset + 0 * VECTOR_SIZE));
            output[7] = Avx.LoadVector256((uint*)(inputs[7] + blockOffset + 0 * VECTOR_SIZE));
            output[8] = Avx.LoadVector256((uint*)(inputs[0] + blockOffset + 1 * VECTOR_SIZE));
            output[9] = Avx.LoadVector256((uint*)(inputs[1] + blockOffset + 1 * VECTOR_SIZE));
            output[10] = Avx.LoadVector256((uint*)(inputs[2] + blockOffset + 1 * VECTOR_SIZE));
            output[11] = Avx.LoadVector256((uint*)(inputs[3] + blockOffset + 1 * VECTOR_SIZE));
            output[12] = Avx.LoadVector256((uint*)(inputs[4] + blockOffset + 1 * VECTOR_SIZE));
            output[13] = Avx.LoadVector256((uint*)(inputs[5] + blockOffset + 1 * VECTOR_SIZE));
            output[14] = Avx.LoadVector256((uint*)(inputs[6] + blockOffset + 1 * VECTOR_SIZE));
            output[15] = Avx.LoadVector256((uint*)(inputs[7] + blockOffset + 1 * VECTOR_SIZE));

            for (int i = 0; i < 8; i++)
            {
                // TODO why prefetch the input into all cache levels and not the output?
                Sse.Prefetch0(inputs[i] + blockOffset + 256);
            }
            TransposeVectors(output);
            TransposeVectors(output + 8);
        }
        #endregion private methods
    }
}
