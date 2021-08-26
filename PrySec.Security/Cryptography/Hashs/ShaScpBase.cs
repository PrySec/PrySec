using PrySec.Base.Memory;
using PrySec.Base.Primitives;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashs
{
    public abstract unsafe class ShaScpBase
    {
        public DeterministicSpan<byte> ComputeHash<T>(IUnmanaged<T> memory) where T : unmanaged
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

            // create a new sha state
            ShaScpState state = new(allocatedSize, blockCount, dataLength);

            // initialize buffer and add padding
            Initialize(memory, ref state);

            // calculate the hash
            DeterministicSpan<byte> result = HashCore(ref state);

            // free the state
            state.Free();
            return result;
        }

        private protected static DeterministicSpan<byte> HashFinalize(ref ShaScpState state, ref DeterministicSpan<uint> resultBuffer, ref UnsafeReference<uint> messageScheduleBuffer)
        {
            // Zero used stack memory
            new Span<uint>(messageScheduleBuffer.Pointer, messageScheduleBuffer.Size).Fill(0x0);

            // Fix endianness
            for (int i = 0; i < resultBuffer.Size; i++)
            {
                resultBuffer.BasePointer[i] = (UInt32BE)resultBuffer.BasePointer[i];
            }
            return resultBuffer.CastAs<byte>();
        }

        private protected abstract DeterministicSpan<byte> HashCore(ref ShaScpState state);

        private static void Initialize<T>(IUnmanaged<T> memory, ref ShaScpState state) where T : unmanaged
        {
            using (IMemoryAccess<T> memoryAccess = memory.GetAccess())
            {
                Unsafe.CopyBlockUnaligned(state.Buffer.BasePointer, memoryAccess.Pointer, memoryAccess.ByteSize);
            }

            // append padding
            ((byte*)state.Buffer.BasePointer)[state.DataLength] = 0x80;

            // calculate length of original message in bits
            // write message length as 64 bit big endian unsigned integer to the end of the buffer
            *(ulong*)(state.Buffer.BasePointer + state.Buffer.Size - 2) = (UInt64BE)(((ulong)state.DataLength) << 3);

            // convert 32 bit word wise back to little endian.
            for (int i = 0; i < state.AllocatedSize; i++)
            {
                state.Buffer.BasePointer[i] = (UInt32BE)state.Buffer.BasePointer[i];
            }
        }

        protected readonly ref struct ShaScpState
        {
            public readonly int AllocatedSize;
            public readonly int BlockCount;
            public readonly DeterministicSpan<uint> Buffer;
            public readonly int DataLength;

            public ShaScpState(int allocatedSize, int blockCount, int dataLength)
            {
                Buffer = new DeterministicSpan<uint>(allocatedSize);
                Buffer.ZeroMemory();
                BlockCount = blockCount;
                AllocatedSize = allocatedSize;
                DataLength = dataLength;
            }

            public void Free()
            {
                Buffer.Free();
            }
        }
    }
}