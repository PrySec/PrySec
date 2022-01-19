using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Sha;

public abstract unsafe class ShaUInt32Scp : ShaScpBase<uint>
{
    protected ShaUInt32Scp()
    {
    }

    private protected override void Initialize<T>(IUnmanaged<T> input, ref ShaScpState state)
    {
        if (input.ByteSize > 0)
        {
            using IMemoryAccess<T> memoryAccess = input.GetAccess();
            Unsafe.CopyBlockUnaligned(state.Buffer.BasePointer, memoryAccess.Pointer, memoryAccess.ByteSize);
        }

        // append padding
        ((byte*)state.Buffer.BasePointer)[state.DataLength] = 0x80;

        // calculate length of original message in bits
        // write message length as 64 bit big endian unsigned integer to the end of the buffer
        *(ulong*)(state.Buffer.BasePointer + state.Buffer.Count - 2) = (UInt64BE_T)((ulong)state.DataLength << 3);

        // convert 32 bit word wise back to little endian.
        for (int i = 0; i < state.AllocatedSize; i++)
        {
            state.Buffer.BasePointer[i] = (UInt32BE_T)state.Buffer.BasePointer[i];
        }
    }

    private protected override void HashFinalize<TOutputMemory>(ref ShaScpState state, ref TOutputMemory resultBuffer, ref UnsafeReference<uint> messageScheduleBuffer)
    {
        // Zero used stack memory
        messageScheduleBuffer.SetZero();

        using IMemoryAccess<uint> access = resultBuffer.GetAccess<uint>();

        // Fix endianness
        for (int i = 0; i < access.Count; i++)
        {
            BinaryUtils.WriteUInt32BigEndian(access.Pointer + i, access.Pointer[i]);
        }
    }
}