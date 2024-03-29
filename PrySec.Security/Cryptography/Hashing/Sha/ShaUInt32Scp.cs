﻿using PrySec.Core.HwPrimitives;
using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using System;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Sha;

public abstract unsafe class ShaUInt32Scp : ShaScpBase<uint>
{
    protected ShaUInt32Scp()
    {
    }

    private protected override void Initialize(IUnmanaged input, ref ShaScpState state)
    {
        if (input.ByteSize > 0)
        {
            using IMemoryAccess<byte> memoryAccess = input.GetAccess<byte>();
            Unsafe.CopyBlockUnaligned(state.Buffer.DataPointer, memoryAccess.Pointer, memoryAccess.ByteSize);
        }

        // append padding
        ((byte*)state.Buffer.DataPointer)[state.DataLength] = 0x80;

        // calculate length of original message in bits
        // write message length as 64 bit big endian unsigned integer to the end of the buffer
        *(ulong*)(state.Buffer.DataPointer + state.Buffer.Count - 2) = (UInt64BE_T)((ulong)state.DataLength << 3);

        // convert 32 bit word wise back to little endian.
        for (int i = 0; i < state.AllocatedSize; i++)
        {
            state.Buffer.DataPointer[i] = (UInt32BE_T)state.Buffer.DataPointer[i];
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