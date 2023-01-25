using PrySec.Core;
using PrySec.Core.HwPrimitives;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.Cryptography.Hashing.Blake3.Implementation;
using PrySec.Security.Cryptography.Hashing.Blake3.Implementation.HwIntrinsics;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Security.Cryptography.Hashing.Blake3;

using static Blake3__EffectiveArch;

internal unsafe class Blake3HwIntrinsicsSse41 : IBlake3Implementation
{
    public static uint SimdDegree => 4;

    public static void CompressInPlace(uint* cv, byte* block, uint blockLength, ulong counter, Blake3Flags flags)
    {
        Vector128<uint>* rows = stackalloc Vector128<uint>[4];
        CompressPre(rows, cv, block, blockLength, counter, flags);
        Sse2.Store(&cv[0], Sse2.Xor(rows[0], rows[2]));
        Sse2.Store(&cv[4], Sse2.Xor(rows[1], rows[3]));
    }

    public static void CompressXof(uint* cv, byte* block, uint blockLength, ulong counter, Blake3Flags flags, byte* output)
    {
        Vector128<uint>* rows = stackalloc Vector128<uint>[4];
        CompressPre(rows, cv, block, blockLength, counter, flags);
        Sse2.Store((uint*)&output[0], Sse2.Xor(rows[0], rows[2]));
        Sse2.Store((uint*)&output[16], Sse2.Xor(rows[1], rows[3]));
        Sse2.Store((uint*)&output[32], Sse2.Xor(rows[2], Sse2.LoadVector128(&cv[0])));
        Sse2.Store((uint*)&output[48], Sse2.Xor(rows[3], Sse2.LoadVector128(&cv[4])));
    }

    public static void HashMany(byte** inputs, ulong inputCount, uint blockCount, uint* key, ulong counter,
        bool incrementCounter, Blake3Flags flags, Blake3Flags flagsStart, Blake3Flags flagsEnd, byte* output)
    {
        while (inputCount >= SimdDegree)
        {
            Hash4Sse41(inputs, blockCount, key, counter, incrementCounter, flags, flagsStart, flagsEnd, output);
            if (incrementCounter)
            {
                counter += (uint)SimdDegree;
            }
            inputs += SimdDegree;
            inputCount -= SimdDegree;
            output = &output[SimdDegree * BLAKE3_OUT_LEN];
        }
        uint* cv = stackalloc uint[8];
        while (inputCount > 0)
        {
            HashOne(inputs[0], blockCount, key, counter, flags, flagsStart, flagsEnd, output, cv);
            if (incrementCounter)
            {
                counter++;
            }
            inputs++;
            inputCount--;
            output += BLAKE3_OUT_LEN;
        }
    }

    #region private methods

    const int VECTOR_SIZE = 4 * sizeof(uint);

    private static readonly Vector128<byte> _rot8Data;
    private static readonly Vector128<byte> _rot16Data;
    private static readonly Vector128<int> _ctrAdd0Data;

    static Blake3HwIntrinsicsSse41()
    {
        ulong* buf = stackalloc ulong[2];

        // write and read in whatever endianness we have
        buf[0] = 0x0407060500030201uL;
        buf[1] = 0x0C0F0E0D080B0A09uL;
        _rot8Data = Sse2.LoadVector128((byte*)buf);

        buf[0] = 0x0504070601000302uL;
        buf[1] = 0x0D0C0F0E09080B0AuL;
        _rot16Data = Sse2.LoadVector128((byte*)buf);

        buf[0] = 0x0000000100000000uL;
        buf[1] = 0x0000000300000002uL;
        _ctrAdd0Data = Sse2.LoadVector128((int*)buf);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> Rot16(Vector128<uint> x) =>
        Ssse3.Shuffle(x.As<uint, byte>(), _rot16Data).As<byte, uint>();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> Rot12(Vector128<uint> x) =>
        Sse2.Or(Sse2.ShiftRightLogical(x, 12), Sse2.ShiftLeftLogical(x, 32 - 12));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> Rot8(Vector128<uint> x) =>
        Ssse3.Shuffle(x.As<uint, byte>(), _rot8Data).As<byte, uint>();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> Rot7(Vector128<uint> x) =>
        Sse2.Or(Sse2.ShiftRightLogical(x, 7), Sse2.ShiftLeftLogical(x, 32 - 7));

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static Vector128<uint> ShufflePs2(Vector128<uint> a, Vector128<uint> b, byte c) =>
        Sse.Shuffle(a.AsSingle(), b.AsSingle(), c).AsUInt32();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G1(Vector128<uint>* row0, Vector128<uint>* row1,
        Vector128<uint>* row2, Vector128<uint>* row3, Vector128<uint> m)
    {
        *row0 = Sse2.Add(Sse2.Add(*row0, m), *row1);
        *row3 = Sse2.Xor(*row3, *row0);
        *row3 = Rot16(*row3);
        *row2 = Sse2.Add(*row2, *row3);
        *row1 = Sse2.Xor(*row1, *row2);
        *row1 = Rot12(*row1);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void G2(Vector128<uint>* row0, Vector128<uint>* row1,
        Vector128<uint>* row2, Vector128<uint>* row3, Vector128<uint> m)
    {
        *row0 = Sse2.Add(Sse2.Add(*row0, m), *row1);
        *row3 = Sse2.Xor(*row3, *row0);
        *row3 = Rot8(*row3);
        *row2 = Sse2.Add(*row2, *row3);
        *row1 = Sse2.Xor(*row1, *row2);
        *row1 = Rot7(*row1);
    }

    // Note the optimization here of leaving row1 as the unrotated row, rather than
    // row0. All the message loads below are adjusted to compensate for this. See
    // discussion at https://github.com/sneves/blake2-avx2/pull/4
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Diagonalize(Vector128<uint>* row0, Vector128<uint>* row2, Vector128<uint>* row3)
    {
        *row0 = Sse2.Shuffle(*row0, AvxPrimitives._MM_SHUFFLE(2, 1, 0, 3));
        *row3 = Sse2.Shuffle(*row3, AvxPrimitives._MM_SHUFFLE(1, 0, 3, 2));
        *row2 = Sse2.Shuffle(*row2, AvxPrimitives._MM_SHUFFLE(0, 3, 2, 1));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void Undiagonalize(Vector128<uint>* row0, Vector128<uint>* row2, Vector128<uint>* row3)
    {
        *row0 = Sse2.Shuffle(*row0, AvxPrimitives._MM_SHUFFLE(0, 3, 2, 1));
        *row3 = Sse2.Shuffle(*row3, AvxPrimitives._MM_SHUFFLE(1, 0, 3, 2));
        *row2 = Sse2.Shuffle(*row2, AvxPrimitives._MM_SHUFFLE(2, 1, 0, 3));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void CompressPre(Vector128<uint>* rows, uint* cv, byte* block, uint blockLength, ulong counter, Blake3Flags flags)
    {
        rows[0] = Sse2.LoadVector128(&cv[0]);
        rows[1] = Sse2.LoadVector128(&cv[4]);
        rows[2] = Vector128.Create(IV[0], IV[1], IV[2], IV[3]);
        rows[3] = Vector128.Create(CounterLow(counter), CounterHigh(counter), blockLength, (uint)flags);

        Vector128<uint> m0 = Sse2.LoadVector128(&block[VECTOR_SIZE * 0]).AsUInt32();
        Vector128<uint> m1 = Sse2.LoadVector128(&block[VECTOR_SIZE * 1]).AsUInt32();
        Vector128<uint> m2 = Sse2.LoadVector128(&block[VECTOR_SIZE * 2]).AsUInt32();
        Vector128<uint> m3 = Sse2.LoadVector128(&block[VECTOR_SIZE * 3]).AsUInt32();

        Vector128<uint> t0, t1, t2, t3, tt;

        // Round 1. The first round permutes the message words from the original
        // input order, into the groups that get mixed in parallel.
        t0 = ShufflePs2(m0, m1, AvxPrimitives._MM_SHUFFLE(2, 0, 2, 0)); //  6  4  2  0
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
        t1 = ShufflePs2(m0, m1, AvxPrimitives._MM_SHUFFLE(3, 1, 3, 1)); //  7  5  3  1
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
        Diagonalize(&rows[0], &rows[2], &rows[3]);
        t2 = ShufflePs2(m2, m3, AvxPrimitives._MM_SHUFFLE(2, 0, 2, 0)); // 14 12 10  8
        t2 = Sse2.Shuffle(t2, AvxPrimitives._MM_SHUFFLE(2, 1, 0, 3));   // 12 10  8 14
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
        t3 = ShufflePs2(m2, m3, AvxPrimitives._MM_SHUFFLE(3, 1, 3, 1)); // 15 13 11  9
        t3 = Sse2.Shuffle(t3, AvxPrimitives._MM_SHUFFLE(2, 1, 0, 3));   // 13 11  9 15
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
        Undiagonalize(&rows[0], &rows[2], &rows[3]);
        m0 = t0;
        m1 = t1;
        m2 = t2;
        m3 = t3;

        // Round 2. This round and all following rounds apply a fixed permutation
        // to the message words from the round before.
        t0 = ShufflePs2(m0, m1, AvxPrimitives._MM_SHUFFLE(3, 1, 1, 2));
        t0 = Sse2.Shuffle(t0, AvxPrimitives._MM_SHUFFLE(0, 3, 2, 1));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
        t1 = ShufflePs2(m2, m3, AvxPrimitives._MM_SHUFFLE(3, 3, 2, 2));
        tt = Sse2.Shuffle(m0, AvxPrimitives._MM_SHUFFLE(0, 0, 3, 3));
        t1 = Sse41.Blend(tt.AsUInt16(), t1.AsUInt16(), 0xCC).AsUInt32();
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
        Diagonalize(&rows[0], &rows[2], &rows[3]);
        t2 = Sse2.UnpackLow(m3.AsUInt64(), m1.AsUInt64()).AsUInt32();
        tt = Sse41.Blend(t2.AsUInt16(), m2.AsUInt16(), 0xC0).AsUInt32();
        t2 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(1, 3, 2, 0));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
        t3 = Sse2.UnpackHigh(m1, m3);
        tt = Sse2.UnpackLow(m2, t3);
        t3 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(0, 1, 3, 2));
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
        Undiagonalize(&rows[0], &rows[2], &rows[3]);
        m0 = t0;
        m1 = t1;
        m2 = t2;
        m3 = t3;

        // Round 3
        t0 = ShufflePs2(m0, m1, AvxPrimitives._MM_SHUFFLE(3, 1, 1, 2));
        t0 = Sse2.Shuffle(t0, AvxPrimitives._MM_SHUFFLE(0, 3, 2, 1));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
        t1 = ShufflePs2(m2, m3, AvxPrimitives._MM_SHUFFLE(3, 3, 2, 2));
        tt = Sse2.Shuffle(m0, AvxPrimitives._MM_SHUFFLE(0, 0, 3, 3));
        t1 = Sse41.Blend(tt.AsUInt16(), t1.AsUInt16(), 0xCC).AsUInt32();
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
        Diagonalize(&rows[0], &rows[2], &rows[3]);
        t2 = Sse2.UnpackLow(m3.AsUInt64(), m1.AsUInt64()).AsUInt32();
        tt = Sse41.Blend(t2.AsUInt16(), m2.AsUInt16(), 0xC0).AsUInt32();
        t2 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(1, 3, 2, 0));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
        t3 = Sse2.UnpackHigh(m1, m3);
        tt = Sse2.UnpackLow(m2, t3);
        t3 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(0, 1, 3, 2));
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
        Undiagonalize(&rows[0], &rows[2], &rows[3]);
        m0 = t0;
        m1 = t1;
        m2 = t2;
        m3 = t3;

        // Round 4
        t0 = ShufflePs2(m0, m1, AvxPrimitives._MM_SHUFFLE(3, 1, 1, 2));
        t0 = Sse2.Shuffle(t0, AvxPrimitives._MM_SHUFFLE(0, 3, 2, 1));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
        t1 = ShufflePs2(m2, m3, AvxPrimitives._MM_SHUFFLE(3, 3, 2, 2));
        tt = Sse2.Shuffle(m0, AvxPrimitives._MM_SHUFFLE(0, 0, 3, 3));
        t1 = Sse41.Blend(tt.AsUInt16(), t1.AsUInt16(), 0xCC).AsUInt32();
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
        Diagonalize(&rows[0], &rows[2], &rows[3]);
        t2 = Sse2.UnpackLow(m3.AsUInt64(), m1.AsUInt64()).AsUInt32();
        tt = Sse41.Blend(t2.AsUInt16(), m2.AsUInt16(), 0xC0).AsUInt32();
        t2 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(1, 3, 2, 0));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
        t3 = Sse2.UnpackHigh(m1, m3);
        tt = Sse2.UnpackLow(m2, t3);
        t3 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(0, 1, 3, 2));
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
        Undiagonalize(&rows[0], &rows[2], &rows[3]);
        m0 = t0;
        m1 = t1;
        m2 = t2;
        m3 = t3;

        // Round 5
        t0 = ShufflePs2(m0, m1, AvxPrimitives._MM_SHUFFLE(3, 1, 1, 2));
        t0 = Sse2.Shuffle(t0, AvxPrimitives._MM_SHUFFLE(0, 3, 2, 1));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
        t1 = ShufflePs2(m2, m3, AvxPrimitives._MM_SHUFFLE(3, 3, 2, 2));
        tt = Sse2.Shuffle(m0, AvxPrimitives._MM_SHUFFLE(0, 0, 3, 3));
        t1 = Sse41.Blend(tt.AsUInt16(), t1.AsUInt16(), 0xCC).AsUInt32();
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
        Diagonalize(&rows[0], &rows[2], &rows[3]);
        t2 = Sse2.UnpackLow(m3.AsUInt64(), m1.AsUInt64()).AsUInt32();
        tt = Sse41.Blend(t2.AsUInt16(), m2.AsUInt16(), 0xC0).AsUInt32();
        t2 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(1, 3, 2, 0));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
        t3 = Sse2.UnpackHigh(m1, m3);
        tt = Sse2.UnpackLow(m2, t3);
        t3 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(0, 1, 3, 2));
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
        Undiagonalize(&rows[0], &rows[2], &rows[3]);
        m0 = t0;
        m1 = t1;
        m2 = t2;
        m3 = t3;

        // Round 6
        t0 = ShufflePs2(m0, m1, AvxPrimitives._MM_SHUFFLE(3, 1, 1, 2));
        t0 = Sse2.Shuffle(t0, AvxPrimitives._MM_SHUFFLE(0, 3, 2, 1));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
        t1 = ShufflePs2(m2, m3, AvxPrimitives._MM_SHUFFLE(3, 3, 2, 2));
        tt = Sse2.Shuffle(m0, AvxPrimitives._MM_SHUFFLE(0, 0, 3, 3));
        t1 = Sse41.Blend(tt.AsUInt16(), t1.AsUInt16(), 0xCC).AsUInt32();
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
        Diagonalize(&rows[0], &rows[2], &rows[3]);
        t2 = Sse2.UnpackLow(m3.AsUInt64(), m1.AsUInt64()).AsUInt32();
        tt = Sse41.Blend(t2.AsUInt16(), m2.AsUInt16(), 0xC0).AsUInt32();
        t2 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(1, 3, 2, 0));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
        t3 = Sse2.UnpackHigh(m1, m3);
        tt = Sse2.UnpackLow(m2, t3);
        t3 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(0, 1, 3, 2));
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
        Undiagonalize(&rows[0], &rows[2], &rows[3]);
        m0 = t0;
        m1 = t1;
        m2 = t2;
        m3 = t3;

        // Round 7
        t0 = ShufflePs2(m0, m1, AvxPrimitives._MM_SHUFFLE(3, 1, 1, 2));
        t0 = Sse2.Shuffle(t0, AvxPrimitives._MM_SHUFFLE(0, 3, 2, 1));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t0);
        t1 = ShufflePs2(m2, m3, AvxPrimitives._MM_SHUFFLE(3, 3, 2, 2));
        tt = Sse2.Shuffle(m0, AvxPrimitives._MM_SHUFFLE(0, 0, 3, 3));
        t1 = Sse41.Blend(tt.AsUInt16(), t1.AsUInt16(), 0xCC).AsUInt32();
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t1);
        Diagonalize(&rows[0], &rows[2], &rows[3]);
        t2 = Sse2.UnpackLow(m3.AsUInt64(), m1.AsUInt64()).AsUInt32();
        tt = Sse41.Blend(t2.AsUInt16(), m2.AsUInt16(), 0xC0).AsUInt32();
        t2 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(1, 3, 2, 0));
        G1(&rows[0], &rows[1], &rows[2], &rows[3], t2);
        t3 = Sse2.UnpackHigh(m1, m3);
        tt = Sse2.UnpackLow(m2, t3);
        t3 = Sse2.Shuffle(tt, AvxPrimitives._MM_SHUFFLE(0, 1, 3, 2));
        G2(&rows[0], &rows[1], &rows[2], &rows[3], t3);
        Undiagonalize(&rows[0], &rows[2], &rows[3]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void RoundFunction(Vector128<uint>* v, Vector128<uint>* m, uint r)
    {
        v[0] = Sse2.Add(v[0], m[MSG_SCHEDULE[r, 0]]);
        v[1] = Sse2.Add(v[1], m[MSG_SCHEDULE[r, 2]]);
        v[2] = Sse2.Add(v[2], m[MSG_SCHEDULE[r, 4]]);
        v[3] = Sse2.Add(v[3], m[MSG_SCHEDULE[r, 6]]);
        v[0] = Sse2.Add(v[0], v[4]);
        v[1] = Sse2.Add(v[1], v[5]);
        v[2] = Sse2.Add(v[2], v[6]);
        v[3] = Sse2.Add(v[3], v[7]);
        v[12] = Sse2.Xor(v[12], v[0]);
        v[13] = Sse2.Xor(v[13], v[1]);
        v[14] = Sse2.Xor(v[14], v[2]);
        v[15] = Sse2.Xor(v[15], v[3]);
        v[12] = Rot16(v[12]);
        v[13] = Rot16(v[13]);
        v[14] = Rot16(v[14]);
        v[15] = Rot16(v[15]);
        v[8] = Sse2.Add(v[8], v[12]);
        v[9] = Sse2.Add(v[9], v[13]);
        v[10] = Sse2.Add(v[10], v[14]);
        v[11] = Sse2.Add(v[11], v[15]);
        v[4] = Sse2.Xor(v[4], v[8]);
        v[5] = Sse2.Xor(v[5], v[9]);
        v[6] = Sse2.Xor(v[6], v[10]);
        v[7] = Sse2.Xor(v[7], v[11]);
        v[4] = Rot12(v[4]);
        v[5] = Rot12(v[5]);
        v[6] = Rot12(v[6]);
        v[7] = Rot12(v[7]);
        v[0] = Sse2.Add(v[0], m[MSG_SCHEDULE[r, 1]]);
        v[1] = Sse2.Add(v[1], m[MSG_SCHEDULE[r, 3]]);
        v[2] = Sse2.Add(v[2], m[MSG_SCHEDULE[r, 5]]);
        v[3] = Sse2.Add(v[3], m[MSG_SCHEDULE[r, 7]]);
        v[0] = Sse2.Add(v[0], v[4]);
        v[1] = Sse2.Add(v[1], v[5]);
        v[2] = Sse2.Add(v[2], v[6]);
        v[3] = Sse2.Add(v[3], v[7]);
        v[12] = Sse2.Xor(v[12], v[0]);
        v[13] = Sse2.Xor(v[13], v[1]);
        v[14] = Sse2.Xor(v[14], v[2]);
        v[15] = Sse2.Xor(v[15], v[3]);
        v[12] = Rot8(v[12]);
        v[13] = Rot8(v[13]);
        v[14] = Rot8(v[14]);
        v[15] = Rot8(v[15]);
        v[8] = Sse2.Add(v[8], v[12]);
        v[9] = Sse2.Add(v[9], v[13]);
        v[10] = Sse2.Add(v[10], v[14]);
        v[11] = Sse2.Add(v[11], v[15]);
        v[4] = Sse2.Xor(v[4], v[8]);
        v[5] = Sse2.Xor(v[5], v[9]);
        v[6] = Sse2.Xor(v[6], v[10]);
        v[7] = Sse2.Xor(v[7], v[11]);
        v[4] = Rot7(v[4]);
        v[5] = Rot7(v[5]);
        v[6] = Rot7(v[6]);
        v[7] = Rot7(v[7]);

        v[0] = Sse2.Add(v[0], m[MSG_SCHEDULE[r, 8]]);
        v[1] = Sse2.Add(v[1], m[MSG_SCHEDULE[r, 10]]);
        v[2] = Sse2.Add(v[2], m[MSG_SCHEDULE[r, 12]]);
        v[3] = Sse2.Add(v[3], m[MSG_SCHEDULE[r, 14]]);
        v[0] = Sse2.Add(v[0], v[5]);
        v[1] = Sse2.Add(v[1], v[6]);
        v[2] = Sse2.Add(v[2], v[7]);
        v[3] = Sse2.Add(v[3], v[4]);
        v[15] = Sse2.Xor(v[15], v[0]);
        v[12] = Sse2.Xor(v[12], v[1]);
        v[13] = Sse2.Xor(v[13], v[2]);
        v[14] = Sse2.Xor(v[14], v[3]);
        v[15] = Rot16(v[15]);
        v[12] = Rot16(v[12]);
        v[13] = Rot16(v[13]);
        v[14] = Rot16(v[14]);
        v[10] = Sse2.Add(v[10], v[15]);
        v[11] = Sse2.Add(v[11], v[12]);
        v[8] = Sse2.Add(v[8], v[13]);
        v[9] = Sse2.Add(v[9], v[14]);
        v[5] = Sse2.Xor(v[5], v[10]);
        v[6] = Sse2.Xor(v[6], v[11]);
        v[7] = Sse2.Xor(v[7], v[8]);
        v[4] = Sse2.Xor(v[4], v[9]);
        v[5] = Rot12(v[5]);
        v[6] = Rot12(v[6]);
        v[7] = Rot12(v[7]);
        v[4] = Rot12(v[4]);
        v[0] = Sse2.Add(v[0], m[MSG_SCHEDULE[r, 9]]);
        v[1] = Sse2.Add(v[1], m[MSG_SCHEDULE[r, 11]]);
        v[2] = Sse2.Add(v[2], m[MSG_SCHEDULE[r, 13]]);
        v[3] = Sse2.Add(v[3], m[MSG_SCHEDULE[r, 15]]);
        v[0] = Sse2.Add(v[0], v[5]);
        v[1] = Sse2.Add(v[1], v[6]);
        v[2] = Sse2.Add(v[2], v[7]);
        v[3] = Sse2.Add(v[3], v[4]);
        v[15] = Sse2.Xor(v[15], v[0]);
        v[12] = Sse2.Xor(v[12], v[1]);
        v[13] = Sse2.Xor(v[13], v[2]);
        v[14] = Sse2.Xor(v[14], v[3]);
        v[15] = Rot8(v[15]);
        v[12] = Rot8(v[12]);
        v[13] = Rot8(v[13]);
        v[14] = Rot8(v[14]);
        v[10] = Sse2.Add(v[10], v[15]);
        v[11] = Sse2.Add(v[11], v[12]);
        v[8] = Sse2.Add(v[8], v[13]);
        v[9] = Sse2.Add(v[9], v[14]);
        v[5] = Sse2.Xor(v[5], v[10]);
        v[6] = Sse2.Xor(v[6], v[11]);
        v[7] = Sse2.Xor(v[7], v[8]);
        v[4] = Sse2.Xor(v[4], v[9]);
        v[5] = Rot7(v[5]);
        v[6] = Rot7(v[6]);
        v[7] = Rot7(v[7]);
        v[4] = Rot7(v[4]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void TransposeVectors(Vector128<uint>* vecs)
    {
        // Interleave 32-bit lates. The low unpack is lanes 00/11 and the high is
        // 22/33. Note that this doesn't split the vector into two lanes, as the
        // AVX2 counterparts do.
        Vector128<uint> ab_01 = Sse2.UnpackLow(vecs[0], vecs[1]);
        Vector128<uint> ab_23 = Sse2.UnpackHigh(vecs[0], vecs[1]);
        Vector128<uint> cd_01 = Sse2.UnpackLow(vecs[2], vecs[3]);
        Vector128<uint> cd_23 = Sse2.UnpackHigh(vecs[2], vecs[3]);

        // Interleave 64-bit lanes.
        Vector128<uint> abcd_0 = Sse2.UnpackLow(ab_01.AsUInt64(), cd_01.AsUInt64()).AsUInt32();
        Vector128<uint> abcd_1 = Sse2.UnpackHigh(ab_01.AsUInt64(), cd_01.AsUInt64()).AsUInt32();
        Vector128<uint> abcd_2 = Sse2.UnpackLow(ab_23.AsUInt64(), cd_23.AsUInt64()).AsUInt32();
        Vector128<uint> abcd_3 = Sse2.UnpackHigh(ab_23.AsUInt64(), cd_23.AsUInt64()).AsUInt32();

        vecs[0] = abcd_0;
        vecs[1] = abcd_1;
        vecs[2] = abcd_2;
        vecs[3] = abcd_3;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void TransposeMessageVectors(byte** inputs, uint blockOffset, Vector128<uint>* output)
    {
        output[0] = Sse2.LoadVector128((uint*)&inputs[0][blockOffset + (0 * VECTOR_SIZE)]);
        output[1] = Sse2.LoadVector128((uint*)&inputs[1][blockOffset + (0 * VECTOR_SIZE)]);
        output[2] = Sse2.LoadVector128((uint*)&inputs[2][blockOffset + (0 * VECTOR_SIZE)]);
        output[3] = Sse2.LoadVector128((uint*)&inputs[3][blockOffset + (0 * VECTOR_SIZE)]);
        output[4] = Sse2.LoadVector128((uint*)&inputs[0][blockOffset + (1 * VECTOR_SIZE)]);
        output[5] = Sse2.LoadVector128((uint*)&inputs[1][blockOffset + (1 * VECTOR_SIZE)]);
        output[6] = Sse2.LoadVector128((uint*)&inputs[2][blockOffset + (1 * VECTOR_SIZE)]);
        output[7] = Sse2.LoadVector128((uint*)&inputs[3][blockOffset + (1 * VECTOR_SIZE)]);
        output[8] = Sse2.LoadVector128((uint*)&inputs[0][blockOffset + (2 * VECTOR_SIZE)]);
        output[9] = Sse2.LoadVector128((uint*)&inputs[1][blockOffset + (2 * VECTOR_SIZE)]);
        output[10] = Sse2.LoadVector128((uint*)&inputs[2][blockOffset + (2 * VECTOR_SIZE)]);
        output[11] = Sse2.LoadVector128((uint*)&inputs[3][blockOffset + (2 * VECTOR_SIZE)]);
        output[12] = Sse2.LoadVector128((uint*)&inputs[0][blockOffset + (3 * VECTOR_SIZE)]);
        output[13] = Sse2.LoadVector128((uint*)&inputs[1][blockOffset + (3 * VECTOR_SIZE)]);
        output[14] = Sse2.LoadVector128((uint*)&inputs[2][blockOffset + (3 * VECTOR_SIZE)]);
        output[15] = Sse2.LoadVector128((uint*)&inputs[3][blockOffset + (3 * VECTOR_SIZE)]);
        for (int i = 0; i < 4; ++i)
        {
            // TODO why prefetch the input into all cache levels and not the output?
            Sse.Prefetch0(inputs[i] + blockOffset + 256);
        }
        TransposeVectors(&output[0]);
        TransposeVectors(&output[4]);
        TransposeVectors(&output[8]);
        TransposeVectors(&output[12]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void LoadCounters(ulong counter, bool incrementCounter, Vector128<uint>* outLow, Vector128<uint>* outHigh)
    {
        Vector128<int> mask = Vector128.Create(-*(sbyte*)&incrementCounter);
        Vector128<int> add1 = Sse2.And(mask, _ctrAdd0Data);
        Vector128<int> l = Sse2.Add(Vector128.Create((int)counter), add1);
        Vector128<int> carry = Sse2.CompareGreaterThan(
            Sse2.Xor(add1, Vector128.Create(unchecked((int)0x80000000u))),
            Sse2.Xor(l, Vector128.Create(unchecked((int)0x80000000u))));
        Vector128<int> h = Sse2.Subtract(Vector128.Create((int)(counter >> 32)), carry);
        *outLow = l.As<int, uint>();
        *outHigh = h.As<int, uint>();
    }

    private static void Hash4Sse41(byte** inputs, Size_T blocks, uint* key, ulong counter,
        bool incrementCounter, Blake3Flags flags, Blake3Flags flagsStart, Blake3Flags flagsEnd, byte* output)
    {
        Vector128<uint>* v = stackalloc Vector128<uint>[16];
        v[0] = Vector128.Create(key[0]);
        v[1] = Vector128.Create(key[1]);
        v[2] = Vector128.Create(key[2]);
        v[3] = Vector128.Create(key[3]);
        v[4] = Vector128.Create(key[4]);
        v[5] = Vector128.Create(key[5]);
        v[6] = Vector128.Create(key[6]);
        v[7] = Vector128.Create(key[7]);

        Vector128<uint> counterLowVector, counterHighVector;
        LoadCounters(counter, incrementCounter, &counterLowVector, &counterHighVector);
        Blake3Flags blockFlags = flags | flagsStart;

        Vector128<uint>* messageVectors = stackalloc Vector128<uint>[16];
        Vector128<uint> blockLengthVector = Vector128.Create(BLAKE3_BLOCK_LEN);

        for (uint block = 0u; block < blocks; block++)
        {
            if (block + 1 == blocks)
            {
                blockFlags |= flagsEnd;
            }

            Vector128<uint> blockFlagsVector = Vector128.Create((uint)blockFlags);
            TransposeMessageVectors(inputs, block * BLAKE3_BLOCK_LEN, messageVectors);

            v[8] = Vector128.Create(IV[0]);
            v[9] = Vector128.Create(IV[1]);
            v[10] = Vector128.Create(IV[2]);
            v[11] = Vector128.Create(IV[3]);
            v[12] = counterLowVector;
            v[13] = counterHighVector;
            v[14] = blockLengthVector;
            v[15] = blockFlagsVector;

            RoundFunction(v, messageVectors, 0);
            RoundFunction(v, messageVectors, 1);
            RoundFunction(v, messageVectors, 2);
            RoundFunction(v, messageVectors, 3);
            RoundFunction(v, messageVectors, 4);
            RoundFunction(v, messageVectors, 5);
            RoundFunction(v, messageVectors, 6);

            v[0] = Sse2.Xor(v[0], v[8]);
            v[1] = Sse2.Xor(v[1], v[9]);
            v[2] = Sse2.Xor(v[2], v[10]);
            v[3] = Sse2.Xor(v[3], v[11]);
            v[4] = Sse2.Xor(v[4], v[12]);
            v[5] = Sse2.Xor(v[5], v[13]);
            v[6] = Sse2.Xor(v[6], v[14]);
            v[7] = Sse2.Xor(v[7], v[15]);

            blockFlags = flags;
        }

        TransposeVectors(&v[0]);
        TransposeVectors(&v[4]);

        // The first four vecs now contain the first half of each output, and the
        // second four vecs contain the second half of each output.
        Sse2.Store(&output[0 * VECTOR_SIZE], v[0].AsByte());
        Sse2.Store(&output[1 * VECTOR_SIZE], v[4].AsByte());
        Sse2.Store(&output[2 * VECTOR_SIZE], v[1].AsByte());
        Sse2.Store(&output[3 * VECTOR_SIZE], v[5].AsByte());
        Sse2.Store(&output[4 * VECTOR_SIZE], v[2].AsByte());
        Sse2.Store(&output[5 * VECTOR_SIZE], v[6].AsByte());
        Sse2.Store(&output[6 * VECTOR_SIZE], v[3].AsByte());
        Sse2.Store(&output[7 * VECTOR_SIZE], v[7].AsByte());
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void HashOne(byte* input, Size_T blocks, uint* key, ulong counter, Blake3Flags flags, Blake3Flags flagsStart,
        Blake3Flags flagsEnd, byte* output, uint* cv)
    {
        MemoryManager.Memcpy(cv, key, BLAKE3_KEY_LEN);
        Blake3Flags blockFlags = flags | flagsStart;
        while (blocks > 0)
        {
            if (blocks == 1)
            {
                blockFlags |= flagsEnd;
            }
            CompressInPlace(cv, input, BLAKE3_BLOCK_LEN, counter, blockFlags);
            input += BLAKE3_BLOCK_LEN;
            blocks--;
            blockFlags = flags;
        }
        MemoryManager.Memcpy(output, cv, BLAKE3_OUT_LEN);
    }
    #endregion
}