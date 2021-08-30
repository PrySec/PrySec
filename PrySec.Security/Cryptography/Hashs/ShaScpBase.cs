using PrySec.Base.Memory;
using PrySec.Base.Primitives;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashs
{
    public abstract unsafe class ShaScpBase<TWord> : IHashFunctionScp where TWord : unmanaged
    {
        /// <summary>
        /// 2 for 32 bit algorithms, 3 for 64 bit
        /// </summary>
        private readonly int WORD_SIZE_LOG_2;

        private protected ShaScpBase(int wordSizeLog2)
        {
            WORD_SIZE_LOG_2 = wordSizeLog2;
        }

        public DeterministicSpan<byte> ComputeHash<T>(IUnmanaged<T> memory) where T : unmanaged
        {
            int dataLength = memory.ByteSize;

            // convert string msg into blocks (array of 16 32-bit or 64-bit integers) [§5.2.1]
            // length (in words) of content length + 0x80 byte padding + appended length
            int wordLength = (dataLength >> WORD_SIZE_LOG_2) + 3;

            // number of 16-word blocks required to hold the data
            // is equivilant to ceil(wordLength / 16d)
            int blockCount = (wordLength >> 4) + (((-(wordLength & 0xF)) >> 31) & 0x1);

            // blockCount * 16;
            int allocatedSize = blockCount << 4;

            // create a new sha state
            ShaScpState<TWord> state = new(allocatedSize, blockCount, dataLength);

            // initialize buffer and add padding
            Initialize(memory, ref state);

            // calculate the hash
            DeterministicSpan<byte> result = HashCore(ref state);

            // free the state
            state.Free();
            return result;
        }

        private protected abstract DeterministicSpan<byte> HashFinalize(ref ShaScpState<TWord> state, ref DeterministicSpan<TWord> resultBuffer, ref UnsafeReference<TWord> messageScheduleBuffer);

        private protected abstract DeterministicSpan<byte> HashCore(ref ShaScpState<TWord> state);

        private protected abstract void Initialize<T>(IUnmanaged<T> memory, ref ShaScpState<TWord> state) where T : unmanaged;
             
        IUnmanaged<byte> IHashFunctionScp.ComputeHash<T>(IUnmanaged<T> memory) =>
            ComputeHash(memory);

        protected readonly ref struct ShaScpState<T> where T : unmanaged
        {
            public readonly int AllocatedSize;
            public readonly int BlockCount;
            public readonly DeterministicSpan<T> Buffer;
            public readonly int DataLength;

            public ShaScpState(int allocatedSize, int blockCount, int dataLength)
            {
                Buffer = new DeterministicSpan<T>(allocatedSize);
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