using PrySec.Core.Memory.MemoryManagement;
using PrySec.Security.Cryptography.Hashing.Blake3.Implementation;
using PrySec.Security.MemoryProtection.Portable.Sentinels;
using System;
using System.Text;

namespace PrySec.Security.Cryptography.Encryption.Blake3XofOtp;

public unsafe class Blake3XofOtpScp : Blake3__EffectiveArch
{
    public void ComputeInline(byte* target, nuint targetByteSize, string context)
    {
        Blake3Context blake3 = default;
        using DeterministicSentinel<Blake3Context> _ = DeterministicSentinel.Protect(&blake3, 1);
        int contextByteCount = Encoding.UTF8.GetByteCount(context);
        byte* contextBytesPtr = null;
        bool isStackAllocation = true;
        if (contextByteCount < MemoryManager.MaxStackAllocSize)
        {
            byte* pStackContextBytes = stackalloc byte[contextByteCount];
            contextBytesPtr = pStackContextBytes;
        }
        else
        {
            contextBytesPtr = (byte*)MemoryManager.Malloc(contextByteCount);
            isStackAllocation = false;
        }
        Span<byte> contextBytes = new(contextBytesPtr, contextByteCount);
        Encoding.Default.GetBytes(context, contextBytes);
        Blake3Context.InitializeDeriveKey(&blake3, contextBytesPtr, (ulong)contextByteCount);
        if (!isStackAllocation)
        {
            MemoryManager.Free(contextBytesPtr);
        }
        // TODO: update with key / key access
        //Blake3Context.Update(&blake3, key, targetByteSize);
        // TODO: implement custom FinalizeSeek for this. (direct inline XOR with data during finalization)
        nuint b = targetByteSize;
        ulong seek = 0;
        for (; b > BLAKE3_BLOCK_LEN; b -= BLAKE3_BLOCK_LEN, seek += BLAKE3_BLOCK_LEN)
        {
            Blake3Context.FinalizeSeek(&blake3, seek, target + seek, BLAKE3_BLOCK_LEN);
        }

        Blake3Context.FinalizeSeek(&blake3, seek, target + seek, b);
    }
}
