using PrySec.Core.HwPrimitives;
using System.Runtime.CompilerServices;

namespace PrySec.Security.Cryptography.Hashing.Blake3;
public unsafe partial class Blake3
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void LoadKeyWords(byte* key, uint* keyWords)
    {
        uint* keyPtrAsUInt = (uint*)key;
        keyWords[0] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt);
        keyWords[1] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 1);
        keyWords[2] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 2);
        keyWords[3] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 3);
        keyWords[4] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 4);
        keyWords[5] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 5);
        keyWords[6] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 6);
        keyWords[7] = BinaryUtils.ReadUInt32LittleEndian(keyPtrAsUInt + 7);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void StoreCvWords(byte* bytesOut, uint* cvWords)
    {
        uint* bytesOutAsUInt = (uint*)bytesOut;
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt, cvWords[0]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 1, cvWords[1]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 2, cvWords[2]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 3, cvWords[3]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 4, cvWords[4]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 5, cvWords[5]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 6, cvWords[6]);
        BinaryUtils.WriteUInt32LittleEndian(bytesOutAsUInt + 7, cvWords[7]);
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint CounterLow(ulong counter) => (uint)counter;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint CounterHigh(ulong counter) => (uint)(counter >> 32);
}
