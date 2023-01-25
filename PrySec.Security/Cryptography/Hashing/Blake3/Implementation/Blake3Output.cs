using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Portable;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Blake3.Implementation;

using static Blake3__EffectiveArch;

internal unsafe struct Blake3Output
{
    public fixed uint InputCv[BLAKE3_KEY_DWORD_LEN];
    public ulong Counter;
    public fixed byte Block[(int)BLAKE3_BLOCK_LEN];
    public byte BlockLength;
    public Blake3Flags Flags;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Make(Blake3Output* raw, uint* inputCv, byte* block, byte blockLength, ulong counter, Blake3Flags flags)
    {
        Unsafe.CopyBlockUnaligned(raw->InputCv, inputCv, 32);
        Unsafe.CopyBlockUnaligned(raw->Block, block, BLAKE3_BLOCK_LEN);
        raw->BlockLength = blockLength;
        raw->Counter = counter;
        raw->Flags = flags;
    }

    // Chaining values within a given chunk (specifically the compress_in_place
    // interface) are represented as words. This avoids unnecessary bytes<->words
    // conversion overhead in the portable implementation. However, the hash_many
    // interface handles both user input and parent node blocks, so it accepts
    // bytes. For that reason, chaining values in the CV stack are represented as
    // bytes.
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void ChainingValue(Blake3Output* self, byte* cv)
    {
        uint* cvWords = stackalloc uint[8];
        using DeterministicMemory<uint> _ = DeterministicMemory.ProtectOnly(cvWords, 32);
        Unsafe.CopyBlockUnaligned(cvWords, self->InputCv, 32);
        CompressInPlaceImpl(cvWords, self->Block, self->BlockLength, self->Counter, self->Flags);
        StoreCvWords(cv, cvWords);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Parent(Blake3Output* raw, byte* block, uint* key, Blake3Flags flags) =>
        Make(raw, key, block, (byte)BLAKE3_BLOCK_LEN, 0, flags | Blake3Flags.PARENT);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void RootBytes(Blake3Output* self, Blake3Context* context, ulong seek, byte* output, Size_T outputLength)
    {
        ulong outputBlockCounter = seek / BLAKE3_BLOCK_LEN;

        // % will get optimized away by the JIT because BLAKE3_BLOCK_LEN is const.
        nuint offsetWithinBlock = (nuint)(seek % BLAKE3_BLOCK_LEN);

        byte* wideBuffer = stackalloc byte[(int)BLAKE3_BLOCK_LEN];
        while (outputLength > 0)
        {
            CompressXofImpl(self->InputCv,
                             self->Block,
                             self->BlockLength,
                             outputBlockCounter,
                             self->Flags | Blake3Flags.ROOT,
                             wideBuffer);

            nuint availableBytes = BLAKE3_BLOCK_LEN - offsetWithinBlock;
            nuint memcpyLength = outputLength > availableBytes
                ? availableBytes
                : (nuint)outputLength;
            context->BlockFinalizerFunction(output, wideBuffer + offsetWithinBlock, memcpyLength);
            output += memcpyLength;
            outputLength -= memcpyLength;
            outputBlockCounter++;
            offsetWithinBlock = 0;
        }
    }
}