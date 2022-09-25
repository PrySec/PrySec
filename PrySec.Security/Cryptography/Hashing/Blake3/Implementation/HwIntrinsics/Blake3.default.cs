using PrySec.Core;
using PrySec.Core.HwPrimitives;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Blake3;
public unsafe partial class Blake3
{
    private class Blake3HwIntrinsicsDefault : IBlake3Implementation
    {
        public static uint SimdDegree => 1u;

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static void CompressInPlace(uint* cv, byte* block, uint blockLength, ulong counter, Blake3Flags flags)
        {
            uint* state = stackalloc uint[16];
            CompressInPlaceHelper(cv, block, blockLength, counter, flags, state);
        }

        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static void CompressXof(uint* cv, byte* block, uint blockLength, ulong counter, Blake3Flags flags, byte* output)
        {
            uint* state = stackalloc uint[16];
            CompressPre(state, cv, block, blockLength, counter, flags);

            uint* out32 = (uint*)output;
            
            BinaryUtils.WriteUInt32LittleEndian(out32, state[0] ^ state[8]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 1, state[1] ^ state[9]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 2, state[2] ^ state[10]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 3, state[3] ^ state[11]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 4, state[4] ^ state[12]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 5, state[5] ^ state[13]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 6, state[6] ^ state[14]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 7, state[7] ^ state[15]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 8, state[8] ^ cv[0]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 9, state[9] ^ cv[1]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 10, state[10] ^ cv[2]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 11, state[11] ^ cv[3]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 12, state[12] ^ cv[4]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 13, state[13] ^ cv[5]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 14, state[14] ^ cv[6]);
            BinaryUtils.WriteUInt32LittleEndian(out32 + 15, state[15] ^ cv[7]);
        }
        
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static void HashMany(byte** inputs, ulong inputCount, uint blockCount, uint* key, ulong counter, bool incrementCounter, Blake3Flags flags, Blake3Flags flagsStart, Blake3Flags flagsEnd, byte* output)
        {
            uint* state = stackalloc uint[16];
            uint* cv = stackalloc uint[8];

            while (inputCount > 0)
            {
                HashOne(*inputs, blockCount, key, counter, flags, flagsStart, flagsEnd, output, cv, state);
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

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CompressInPlaceHelper(uint* cv, byte* block, uint blockLength, ulong counter, Blake3Flags flags, uint* state)
        {
            CompressPre(state, cv, block, blockLength, counter, flags);

            cv[0] = state[0] ^ state[8];
            cv[1] = state[1] ^ state[9];
            cv[2] = state[2] ^ state[10];
            cv[3] = state[3] ^ state[11];
            cv[4] = state[4] ^ state[12];
            cv[5] = state[5] ^ state[13];
            cv[6] = state[6] ^ state[14];
            cv[7] = state[7] ^ state[15];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint RotateRight32(uint w, int c) => (w >> c) | (w << (32 - c));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void G(uint* state, Size_T a, Size_T b, Size_T c, Size_T d, uint x, uint y)
        {
            state[a] = state[a] + state[b] + x;
            state[d] = RotateRight32(state[d] ^ state[a], 16);
            state[c] = state[c] + state[d];
            state[b] = RotateRight32(state[b] ^ state[c], 12);
            state[a] = state[a] + state[b] + y;
            state[d] = RotateRight32(state[d] ^ state[a], 8);
            state[c] = state[c] + state[d];
            state[b] = RotateRight32(state[b] ^ state[c], 7);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void RoundFunction(uint* state, uint* msg, Size_T round, byte* scheduleBase)
        {
            // Select the message schedule based on the round.
            byte* schedule = scheduleBase + round * 16;

            // Mix the columns.
            G(state, 0, 4, 8, 12, msg[schedule[0]], msg[schedule[1]]);
            G(state, 1, 5, 9, 13, msg[schedule[2]], msg[schedule[3]]);
            G(state, 2, 6, 10, 14, msg[schedule[4]], msg[schedule[5]]);
            G(state, 3, 7, 11, 15, msg[schedule[6]], msg[schedule[7]]);

            // Mix the rows.
            G(state, 0, 5, 10, 15, msg[schedule[8]], msg[schedule[9]]);
            G(state, 1, 6, 11, 12, msg[schedule[10]], msg[schedule[11]]);
            G(state, 2, 7, 8, 13, msg[schedule[12]], msg[schedule[13]]);
            G(state, 3, 4, 9, 14, msg[schedule[14]], msg[schedule[15]]);
        }
        
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void CompressPre(uint* state, uint* cv, byte* block, uint blockLength, ulong counter, Blake3Flags flags)
        {
            // stack allocation is fine here.
            uint* blockWords = stackalloc uint[16];
            uint* blockAsUint = (uint*)block;
            blockWords[0] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint);
            blockWords[1] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 1);
            blockWords[2] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 2);
            blockWords[3] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 3);
            blockWords[4] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 4);
            blockWords[5] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 5);
            blockWords[6] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 6);
            blockWords[7] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 7);
            blockWords[8] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 8);
            blockWords[9] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 9);
            blockWords[10] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 10);
            blockWords[11] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 11);
            blockWords[12] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 12);
            blockWords[13] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 13);
            blockWords[14] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 14);
            blockWords[15] = BinaryUtils.ReadUInt32LittleEndian(blockAsUint + 15);

            state[0] = cv[0];
            state[1] = cv[1];
            state[2] = cv[2];
            state[3] = cv[3];
            state[4] = cv[4];
            state[5] = cv[5];
            state[6] = cv[6];
            state[7] = cv[7];
            state[8] = IV[0];
            state[9] = IV[1];
            state[10] = IV[2];
            state[11] = IV[3];
            state[12] = CounterLow(counter);
            state[13] = CounterHigh(counter);
            state[14] = blockLength;
            state[15] = (uint)flags;

            fixed (byte* scheduleBase = MSG_SCHEDULE)
            {
                RoundFunction(state, blockWords, 0, scheduleBase);
                RoundFunction(state, blockWords, 1, scheduleBase);
                RoundFunction(state, blockWords, 2, scheduleBase);
                RoundFunction(state, blockWords, 3, scheduleBase);
                RoundFunction(state, blockWords, 4, scheduleBase);
                RoundFunction(state, blockWords, 5, scheduleBase);
                RoundFunction(state, blockWords, 6, scheduleBase);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void HashOne(byte* input, Size_T blocks, uint* key, ulong counter, Blake3Flags flags, Blake3Flags flagsStart, Blake3Flags flagsEnd, byte* output, uint* cv, uint* state)
        {
            MemoryManager.Memcpy(cv, key, BLAKE3_KEY_LEN);
            Blake3Flags blockFlags = flags | flagsStart;
            while (blocks > 0)
            {
                if (blocks == 1)
                {
                    blockFlags |= flagsEnd;
                }
                CompressInPlaceHelper(cv, input, BLAKE3_BLOCK_LEN, counter, blockFlags, state);
                input += BLAKE3_BLOCK_LEN;
                blocks--;
                blockFlags = flags;
            }
            StoreCvWords(output, cv);
        }
        #endregion
    }
}
