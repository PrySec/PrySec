using PrySec.Core;
using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Security.Cryptography.Hashing.Blake3;
public unsafe partial class Blake3
{
    [StructLayout(LayoutKind.Sequential)]
    private struct Blake3ChunkState
    {
        public fixed uint Cv[8];
        public ulong ChunkCounter;
        public fixed byte Buffer[(int)BLAKE3_BLOCK_LEN];
        public byte BufferLength;
        public byte BlocksCompressed;
        public Blake3Flags Flags;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Initialize(Blake3ChunkState* self, uint* key, Blake3Flags flags)
        {
            Unsafe.CopyBlockUnaligned(self->Cv, key, BLAKE3_KEY_LEN);
            self->ChunkCounter = 0;
            Unsafe.InitBlockUnaligned(self->Buffer, 0, BLAKE3_BLOCK_LEN);
            self->BufferLength = 0;
            self->BlocksCompressed = 0;
            self->Flags = flags;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Reset(Blake3ChunkState* self, uint* key, ulong chunkCounter)
        {
            Unsafe.CopyBlockUnaligned(self->Cv, key, BLAKE3_KEY_LEN);
            self->ChunkCounter = chunkCounter;
            self->BlocksCompressed = 0;
            Unsafe.InitBlockUnaligned(self->Buffer, 0, BLAKE3_BLOCK_LEN);
            self->BufferLength = 0;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint GetLength(Blake3ChunkState* self) =>
            self->BlocksCompressed * BLAKE3_CHUNK_LEN + self->BufferLength;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Update(Blake3ChunkState* self, byte* input, uint inputLength)
        {
            uint take;
            if (self->BufferLength > 0)
            {
                take = FillBuffer(self, input, inputLength);
                input += take;
                inputLength -= take;
                if (inputLength > 0)
                {
                    _compressInPlaceImpl(self->Cv, self->Buffer, BLAKE3_BLOCK_LEN, self->ChunkCounter, self->Flags | MaybeStartFlag(self));
                    self->BlocksCompressed++;
                    self->BufferLength = 0;
                    Unsafe.InitBlockUnaligned(self->Buffer, 0, BLAKE3_BLOCK_LEN);
                }
            }
            while (inputLength > BLAKE3_BLOCK_LEN)
            {
                _compressInPlaceImpl(self->Cv, input, BLAKE3_BLOCK_LEN, self->ChunkCounter, self->Flags | MaybeStartFlag(self));
                self->BlocksCompressed++;
                input += BLAKE3_BLOCK_LEN;
                inputLength -= BLAKE3_BLOCK_LEN;
            }
            take = FillBuffer(self, input, inputLength);
            input += take;
            inputLength -= take;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint FillBuffer(Blake3ChunkState* self, byte* input, uint inputLength)
        {
            uint take = Math.Min(BLAKE3_BLOCK_LEN - self->BufferLength, inputLength);
            byte* destination = self->Buffer + self->BufferLength;
            Unsafe.CopyBlockUnaligned(destination, input, take);
            self->BufferLength += (byte)take;
            return take;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static Blake3Flags MaybeStartFlag(Blake3ChunkState* self) =>
            self->BlocksCompressed == 0
                ? Blake3Flags.CHUNK_START
                : 0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ToOutput(Blake3ChunkState* self, Output_T* output)
        {
            Blake3Flags blockFlags = self->Flags | MaybeStartFlag(self) | Blake3Flags.CHUNK_END;
            Output_T.Make(output, self->Cv, self->Buffer, self->BufferLength, self->ChunkCounter, blockFlags);
        }
    }
}
