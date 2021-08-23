using PrySec.Base.Memory;
using PrySec.Base.Primitives;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashs
{
    public static unsafe class Sha1Scp
    {
        private static readonly uint[] H = new uint[DIGEST_DWORD_LENGTH] 
        {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};

        private const uint H0 = 0x67452301u;
        private const uint H1 = 0xEFCDAB89u;
        private const uint H2 = 0x98BADCFEu;
        private const uint H3 = 0x10325476u;
        private const uint H4 = 0xC3D2E1F0u;

        private const int DIGEST_DWORD_LENGTH = 5;

        private const int DIGEST_LENGTH = DIGEST_DWORD_LENGTH * sizeof(uint);

        private const int MESSAGE_SCHEDULE_BUFFER_LENGTH = 80;

        public static DeterministicSpan<byte> Digest<T>(IUnmanaged<T> memory) where T : unmanaged
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
            // write message length as 64 bit big endian unsigned integer to the end of the buffer
            *(ulong*)(buffer.BasePointer + buffer.Size - 2) = (UInt64BE)(((ulong)dataLength) << 3);

            // convert 32 bit word wise back to little endian.
            for (int i = 0; i < allocatedSize; i++)
            {
                buffer.BasePointer[i] = (UInt32BE)buffer.BasePointer[i];
            }

            // create a 80-entry message schedule array w[0..79] of 32-bit words
            uint* messageScheduleBuffer = stackalloc uint[MESSAGE_SCHEDULE_BUFFER_LENGTH];

            uint h0 = H0;
            uint h1 = H1;
            uint h2 = H2;
            uint h3 = H3;
            uint h4 = H4;

            // Process the message in successive 512 - bit chunks (64 byte blocks / 16 uint blocks)
            for (int i = 0; i < blockCount; i++)
            {
                // copy current chunk (64 bytes) into first 16 words w[0..15] of the message schedule array
                Unsafe.CopyBlockUnaligned(messageScheduleBuffer, buffer.BasePointer + (i << 4), 64);
                int j;
                // Message schedule: extend the sixteen 32-bit words into eighty 32-bit words
                for (j = 16; j < MESSAGE_SCHEDULE_BUFFER_LENGTH; j++)
                {
                    // w[i] = (w[i-3] xor w[i-8] xor w[i-14] xor w[i-16]) leftrotate 1
                    uint tmp = (messageScheduleBuffer[j - 3]
                                ^ messageScheduleBuffer[j - 8]
                                ^ messageScheduleBuffer[j - 14]
                                ^ messageScheduleBuffer[j - 16]);
                    messageScheduleBuffer[j] = (tmp << 1) | (tmp >> 31);
                }

                // Initialize hash value for this chunk
                uint a = h0;
                uint b = h1;
                uint c = h2;
                uint d = h3;
                uint e = h4;

                #region Main compression loop (SCALAR)
                
                uint f, k, temp;

                f = (b & c) | ((~b) & d);
                k = 0x5A827999u;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[0]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[1]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[2]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[3]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[4]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[5]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[6]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[7]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[8]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[9]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[10]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[11]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[12]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[13]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[14]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[15]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[16]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[17]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[18]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                f = (b & c) | ((~b) & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[19]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 20
                f = b ^ c ^ d;
                k = 0x6ED9EBA1u;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[20]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 21
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[21]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 22
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[22]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 23
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[23]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 24
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[24]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 25
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[25]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 26
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[26]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 27
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[27]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 28
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[28]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 29
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[29]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 30
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[30]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 31
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[31]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 32
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[32]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 33
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[33]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 34
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[34]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 35
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[35]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 36
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[36]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 37
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[37]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 38
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[38]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 39
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[39]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 40
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDCu;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[40]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 41
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[41]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 42
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[42]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 43
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[43]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 44
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[44]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 45
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[45]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 46
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[46]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 47
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[47]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 48
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[48]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 49
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[49]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 50
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[50]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 51
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[51]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 52
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[52]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 53
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[53]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 54
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[54]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 55
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[55]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 56
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[56]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 57
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[57]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 58
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[58]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 59
                f = (b & c) | (b & d) | (c & d);
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[59]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 60
                f = b ^ c ^ d;
                k = 0xCA62C1D6u;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[60]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 61
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[61]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 62
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[62]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 63
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[63]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 64
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[64]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 65
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[65]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 66
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[66]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 67
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[67]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 68
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[68]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 69
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[69]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 70
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[70]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 71
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[71]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 72
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[72]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 73
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[73]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 74
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[74]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 75
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[75]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 76
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[76]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 77
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[77]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 78
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[78]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;

                // 79
                f = b ^ c ^ d;
                temp = unchecked(((a << 5) | (a >> 27)) + f + e + k + messageScheduleBuffer[79]);
                e = d;
                d = c;
                c = (b << 30) | (b >> 2);
                b = a;
                a = temp;
                #endregion

                // Add this chunk's hash to result so far
                unchecked
                {
                    h0 += a;
                    h1 += b;
                    h2 += c;
                    h3 += d;
                    h4 += e;
                }
            }

            // Zero used stack memory
            new Span<uint>(messageScheduleBuffer, MESSAGE_SCHEDULE_BUFFER_LENGTH).Fill(0x0);

            // create a buffer to hold the result
            DeterministicSpan<uint> resultBuffer = new(DIGEST_DWORD_LENGTH);
            resultBuffer.BasePointer[0] = (UInt32BE)h0;
            resultBuffer.BasePointer[1] = (UInt32BE)h1;
            resultBuffer.BasePointer[2] = (UInt32BE)h2;
            resultBuffer.BasePointer[3] = (UInt32BE)h3;
            resultBuffer.BasePointer[4] = (UInt32BE)h4;

            return resultBuffer.CastAs<byte>();
        }
    }
}
