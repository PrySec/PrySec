using PrySec.Base.Memory;
using PrySec.Base.Primitives;
using PrySec.Base.Primitives.Converters;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashs
{
    public unsafe class Sha256Scp
    {
        private static readonly uint[] K = new uint[] {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

        private static readonly uint[] H = new uint[] {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

        private const int DIGEST_LENGTH = 32;

        /// <summary>
        /// The length of the message schedule array in 32-bit words.
        /// </summary>
        private const int MESSAGE_SCHEDULE_BUFFER_LENGTH = 64;

        internal static unsafe void PrintMemory(byte* start, int length)
        {
            for (int i = 0; i < length; i++)
            {
                Console.Write(string.Format("{0:x}", start[i]));
                Console.Write(' ');
            }
            Console.WriteLine();
        }

        public DeterministicSpan<byte> Digest<T>(IUnmanaged<T> memory) where T : unmanaged
        {
            int dataLength = memory.ByteSize;
            // convert string msg into 512-bit blocks (array of 16 32-bit integers) [§5.2.1]
            // length (in 32-bit integers) of content length + 0x80 byte padding + appended length
            int int32Length = (dataLength >> 2) + 3;
            // number of 16-integer (512-bit) blocks required to hold the data
            // is equivilant to ceil(int32Length / 16d)
            int blockCount = (int32Length >> 4) + (((-(int32Length & 0xF)) >> 31) & 0x1);
            // blockCount * 16;
            int allocatedSize = blockCount << 4;
            using DeterministicSpan<uint> buffer = new(allocatedSize);
            buffer.ZeroMemory();
            using (IMemoryAccess<T> memoryAccess = memory.GetAccess())
            {
                Unsafe.CopyBlockUnaligned(buffer.BasePointer, memoryAccess.Pointer, memoryAccess.ByteSize);
            }
            // append padding
            ((byte*)buffer.BasePointer)[dataLength] = 0x80;
            // calculate length of original message in bits
            UInt64BE bitLength = (UInt64BE)(((ulong)dataLength) << 3);
            // write message length as 64 bit big endian unsigned integer to the end of the buffer
            *(ulong*)(buffer.BasePointer + buffer.Size - 2) = bitLength;
            // convert 32 bit word wise back to little endian.
            for (int i = 0; i < allocatedSize; i++)
            {
                buffer.BasePointer[i] = (UInt32BE)buffer.BasePointer[i];
            }

            // create a 64-entry message schedule array w[0..63] of 32-bit words
            uint* messageScheduleBuffer = stackalloc uint[MESSAGE_SCHEDULE_BUFFER_LENGTH];

            DeterministicSpan<uint> resultBuffer = new(8);
            fixed (uint* pInitialHash = H)
            {
                Unsafe.CopyBlockUnaligned(resultBuffer.BasePointer, pInitialHash, DIGEST_LENGTH);
            }

            uint* workBuffer = stackalloc uint[8];

            // Process the message in successive 512 - bit chunks (64 byte blocks / 16 uint blocks)
            for (int i = 0; i < blockCount; i++)
            {
                // copy current chunk (64 bytes) into first 16 words w[0..15] of the message schedule array
                Unsafe.CopyBlockUnaligned(messageScheduleBuffer, buffer.BasePointer + (i << 4), 64);
                // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
                for (int j = 16; j < 64; j++)
                {
                    /*
                        s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
                        s1 := (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
                        w[i] := w[i-16] + s0 + w[i-7] + s1
                        */
                    uint s0 = ((messageScheduleBuffer[j - 15] >> 7) | (messageScheduleBuffer[j - 15] << 25))
                        ^ ((messageScheduleBuffer[j - 15] >> 18) | (messageScheduleBuffer[j - 15] << 14))
                        ^ (messageScheduleBuffer[j - 15] >> 3);
                    uint s1 = ((messageScheduleBuffer[j - 2] >> 17) | (messageScheduleBuffer[j - 2] << 15))
                        ^ ((messageScheduleBuffer[j - 2] >> 19) | (messageScheduleBuffer[j - 2] << 13))
                        ^ (messageScheduleBuffer[j - 2] >> 10);
                    messageScheduleBuffer[j] = messageScheduleBuffer[j - 16] + s0 + messageScheduleBuffer[j - 7] + s1;
                }
                Unsafe.CopyBlockUnaligned(workBuffer, resultBuffer.BasePointer, DIGEST_LENGTH);
                for (int j = 0; j < 64; j++)
                {
                    // S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
                    uint s1 = RightRotate(workBuffer[4], 6)
                        ^ RightRotate(workBuffer[4], 11)
                        ^ RightRotate(workBuffer[4], 25);
                    // ch:= (e and f) xor((not e) and g)
                    uint ch = (workBuffer[4] & workBuffer[5]) ^ ((~workBuffer[4]) & workBuffer[6]);
                    // temp1:= h + S1 + ch + k[i] + w[i]
                    uint temp1 = unchecked(workBuffer[7] + s1 + ch + K[j] + messageScheduleBuffer[j]);
                    // S0:= (a rightrotate 2) xor(a rightrotate 13) xor(a rightrotate 22)
                    uint s0 = RightRotate(workBuffer[0], 2)
                        ^ RightRotate(workBuffer[0], 13)
                        ^ RightRotate(workBuffer[0], 22);
                    // maj:= (a and b) xor(a and c) xor(b and c)
                    uint maj = (workBuffer[0] & workBuffer[1])
                        ^ (workBuffer[0] & workBuffer[2])
                        ^ (workBuffer[1] & workBuffer[2]);
                    // temp2:= S0 + maj
                    uint temp2 = s0 + maj;

                    // h:= g
                    workBuffer[7] = workBuffer[6];
                    // g:= f
                    workBuffer[6] = workBuffer[5];
                    // f:= e
                    workBuffer[5] = workBuffer[4];
                    // e:= d + temp1
                    workBuffer[4] = workBuffer[3] + temp1;
                    // d:= c
                    workBuffer[3] = workBuffer[2];
                    // c:= b
                    workBuffer[2] = workBuffer[1];
                    // b:= a
                    workBuffer[1] = workBuffer[0];
                    // a:= temp1 + temp2
                    workBuffer[0] = temp1 + temp2;
                }
                unchecked
                {
                    uint* pResult = resultBuffer.BasePointer;
                    // Add the compressed chunk to the current hash value:
                    // h0:= h0 + a
                    // h1:= h1 + b
                    // h2:= h2 + c
                    // h3:= h3 + d
                    // h4:= h4 + e
                    // h5:= h5 + f
                    // h6:= h6 + g
                    // h7:= h7 + h
                    pResult[0] += workBuffer[0];
                    pResult[1] += workBuffer[1];
                    pResult[2] += workBuffer[2];
                    pResult[3] += workBuffer[3];
                    pResult[4] += workBuffer[4];
                    pResult[5] += workBuffer[5];
                    pResult[6] += workBuffer[6];
                    pResult[7] += workBuffer[7];
                }
            }
            for (int i = 0; i < 8; i++)
            {
                resultBuffer.BasePointer[i] = (UInt32BE)resultBuffer.BasePointer[i];
            }
            return resultBuffer.CastAs<byte>();
        }

        public DeterministicSpan<byte> DigestUnoptimized<T>(IUnmanaged<T> memory) where T : unmanaged
        {
            int dataLength = memory.ByteSize;
            // convert string msg into 512-bit blocks (array of 16 32-bit integers) [§5.2.1]
            // length (in 32-bit integers) of content length + 0x80 byte padding + appended length
            int int32Length = (dataLength >> 2) + 3;
            // number of 16-integer (512-bit) blocks required to hold the data
            // is equivilant to ceil(int32Length / 16d)
            int blockCount = (int32Length >> 4) + (((-(int32Length & 0xF)) >> 31) & 0x1);
            // blockCount * 16;
            int allocatedSize = blockCount << 4;
            using DeterministicSpan<uint> buffer = new(allocatedSize);
            buffer.ZeroMemory();
            using (IMemoryAccess<T> memoryAccess = memory.GetAccess())
            {
                Unsafe.CopyBlockUnaligned(buffer.BasePointer, memoryAccess.Pointer, memoryAccess.ByteSize);
            }
            // append padding
            ((byte*)buffer.BasePointer)[dataLength] = 0x80;
            // calculate length of original message in bits
            UInt64BE bitLength = (UInt64BE)(((ulong)dataLength) << 3);
            // write message length as 64 bit big endian unsigned integer to the end of the buffer
            *(ulong*)(buffer.BasePointer + buffer.Size - 2) = bitLength;
            // convert 32 bit word wise back to little endian.
            for (int i = 0; i < allocatedSize; i++)
            {
                buffer.BasePointer[i] = (UInt32BE)buffer.BasePointer[i];
            }

            // create a 64-entry message schedule array w[0..63] of 32-bit words
            uint* messageScheduleBuffer = stackalloc uint[MESSAGE_SCHEDULE_BUFFER_LENGTH];

            DeterministicSpan<uint> resultBuffer = new(8);
            fixed (uint* pInitialHash = H)
            {
                Unsafe.CopyBlockUnaligned(resultBuffer.BasePointer, pInitialHash, DIGEST_LENGTH);
            }

            uint* workBuffer = stackalloc uint[8];

            // Process the message in successive 512 - bit chunks (64 byte blocks / 16 uint blocks)
            for (int i = 0; i < blockCount; i++)
            {
                // copy current chunk (64 bytes) into first 16 words w[0..15] of the message schedule array
                Unsafe.CopyBlockUnaligned(messageScheduleBuffer, buffer.BasePointer + (i << 4), 64);
                // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array:
                for (int j = 16; j < 64; j++)
                {
                    /*
                        s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift  3)
                        s1 := (w[i- 2] rightrotate 17) xor (w[i- 2] rightrotate 19) xor (w[i- 2] rightshift 10)
                        w[i] := w[i-16] + s0 + w[i-7] + s1
                        */
                    uint s0 = ((messageScheduleBuffer[j - 15] >> 7) | (messageScheduleBuffer[j - 15] << 25))
                        ^ ((messageScheduleBuffer[j - 15] >> 18) | (messageScheduleBuffer[j - 15] << 14))
                        ^ (messageScheduleBuffer[j - 15] >> 3);
                    uint s1 = ((messageScheduleBuffer[j - 2] >> 17) | (messageScheduleBuffer[j - 2] << 15))
                        ^ ((messageScheduleBuffer[j - 2] >> 19) | (messageScheduleBuffer[j - 2] << 13))
                        ^ (messageScheduleBuffer[j - 2] >> 10);
                    messageScheduleBuffer[j] = messageScheduleBuffer[j - 16] + s0 + messageScheduleBuffer[j - 7] + s1;
                }
                Unsafe.CopyBlockUnaligned(workBuffer, resultBuffer.BasePointer, DIGEST_LENGTH);
                for (int j = 0; j < 64; j++)
                {
                    // S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
                    uint s1 = RightRotate(workBuffer[4], 6)
                        ^ RightRotate(workBuffer[4], 11)
                        ^ RightRotate(workBuffer[4], 25);
                    // ch:= (e and f) xor((not e) and g)
                    uint ch = (workBuffer[4] & workBuffer[5]) ^ ((~workBuffer[4]) & workBuffer[6]);
                    // temp1:= h + S1 + ch + k[i] + w[i]
                    uint temp1 = unchecked(workBuffer[7] + s1 + ch + K[j] + messageScheduleBuffer[j]);
                    // S0:= (a rightrotate 2) xor(a rightrotate 13) xor(a rightrotate 22)
                    uint s0 = RightRotate(workBuffer[0], 2)
                        ^ RightRotate(workBuffer[0], 13)
                        ^ RightRotate(workBuffer[0], 22);
                    // maj:= (a and b) xor(a and c) xor(b and c)
                    uint maj = (workBuffer[0] & workBuffer[1])
                        ^ (workBuffer[0] & workBuffer[2])
                        ^ (workBuffer[1] & workBuffer[2]);
                    // temp2:= S0 + maj
                    uint temp2 = s0 + maj;

                    // h:= g
                    workBuffer[7] = workBuffer[6];
                    // g:= f
                    workBuffer[6] = workBuffer[5];
                    // f:= e
                    workBuffer[5] = workBuffer[4];
                    // e:= d + temp1
                    workBuffer[4] = workBuffer[3] + temp1;
                    // d:= c
                    workBuffer[3] = workBuffer[2];
                    // c:= b
                    workBuffer[2] = workBuffer[1];
                    // b:= a
                    workBuffer[1] = workBuffer[0];
                    // a:= temp1 + temp2
                    workBuffer[0] = temp1 + temp2;
                }
                unchecked
                {
                    uint* pResult = resultBuffer.BasePointer;
                    // Add the compressed chunk to the current hash value:
                    // h0:= h0 + a
                    // h1:= h1 + b
                    // h2:= h2 + c
                    // h3:= h3 + d
                    // h4:= h4 + e
                    // h5:= h5 + f
                    // h6:= h6 + g
                    // h7:= h7 + h
                    pResult[0] += workBuffer[0];
                    pResult[1] += workBuffer[1];
                    pResult[2] += workBuffer[2];
                    pResult[3] += workBuffer[3];
                    pResult[4] += workBuffer[4];
                    pResult[5] += workBuffer[5];
                    pResult[6] += workBuffer[6];
                    pResult[7] += workBuffer[7];
                }
            }
            for (int i = 0; i < 8; i++)
            {
                resultBuffer.BasePointer[i] = (UInt32BE)resultBuffer.BasePointer[i];
            }
            return resultBuffer.CastAs<byte>();
        }

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static uint RightRotate(uint source, byte bitCount) =>
            (source >> bitCount) | (source << (32 - bitCount));
    }
}
