using PrySec.Base;
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
    public abstract unsafe class ShaUInt32Scp : ShaScpBase<uint>
    {
        private const int WORD_SIZE_LOG_2 = 2;

        private protected ShaUInt32Scp() : base(WORD_SIZE_LOG_2)
        {
        }

        private protected override void Initialize<T>(IUnmanaged<T> memory, ref ShaScpState<uint> state)
        {
            if (memory.ByteSize > 0)
            {
                using IMemoryAccess<T> memoryAccess = memory.GetAccess();
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

        private protected override DeterministicSpan<byte> HashFinalize(ref ShaScpState<uint> state, ref DeterministicSpan<uint> resultBuffer, ref UnsafeReference<uint> messageScheduleBuffer)
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
    }
}
