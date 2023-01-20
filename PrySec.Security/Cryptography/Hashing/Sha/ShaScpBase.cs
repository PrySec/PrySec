using PrySec.Core.HwPrimitives;
using PrySec.Core.Memory;
using PrySec.Security.MemoryProtection.Portable;

namespace PrySec.Security.Cryptography.Hashing.Sha;

public abstract unsafe class ShaScpBase<TWord> : IHashFunctionScp where TWord : unmanaged
{
    /// <summary>
    /// 2 for 32 bit algorithms, 3 for 64 bit
    /// </summary>
    private protected readonly int WORD_SIZE_LOG_2 = BinaryUtils.Ld(sizeof(TWord));

    /// <summary>
    /// The length in bytes of the final output digest
    /// </summary>
    private protected abstract int DigestOutputLength { get; }

    private protected abstract void HashFinalize<TOutputMemory>(ref ShaScpState state, ref TOutputMemory resultBuffer, ref UnsafeReference<TWord> messageScheduleBuffer)
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>;

    private protected abstract TOutputMemory HashCore<TOutputMemory>(ref ShaScpState state) where TOutputMemory : IUnmanaged<TOutputMemory, byte>;

    private protected abstract void Initialize<T>(IUnmanaged<T> input, ref ShaScpState state) where T : unmanaged;

    IUnmanaged<byte> IHashFunctionScp.ComputeHash<T>(ref IUnmanaged<T> input) =>
        ComputeHash<T, IUnmanaged<T>, DeterministicMemory<byte>>(ref input);

    public TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        int dataLength = input.ByteSize;

        // convert string msg into blocks (array of 16 32-bit or 64-bit integers) [§5.2.1]
        // length (in words) of content length + 0x80 byte padding + appended length
        int wordLength = (dataLength >> WORD_SIZE_LOG_2) + 3;

        // number of 16-word blocks required to hold the data
        // is equivilant to ceil(wordLength / 16d)
        int blockCount = (wordLength >> 4) + (-(wordLength & 0xF) >> 31 & 0x1);

        // blockCount * 16;
        int allocatedSize = blockCount << 4;

        // create a new sha state
        ShaScpState state = new(allocatedSize, blockCount, dataLength);

        // initialize buffer and add padding
        Initialize(input, ref state);

        // calculate the hash
        TOutputMemory result = HashCore<TOutputMemory>(ref state);

        // free the state
        state.Free();
        return result;
    }

    private protected readonly struct ShaScpState
    {
        public readonly int AllocatedSize;
        public readonly int BlockCount;
        public readonly DeterministicMemory<TWord> Buffer;
        public readonly int DataLength;

        public ShaScpState(int allocatedSize, int blockCount, int dataLength)
        {
            Buffer = new DeterministicMemory<TWord>(allocatedSize);
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