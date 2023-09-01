using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives.Converters.Hex.Intrinsics;
using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace PrySec.Core.Primitives.Converters;

public static unsafe class HexConverter
{
    public static byte[] Unhexlify(string hex)
    {
        if (hex.Length == 0)
        {
            return Array.Empty<byte>();
        }
        int inputSize = Encoding.ASCII.GetByteCount(hex);
        if (inputSize % 2 == 1)
        {
            throw new ArgumentException("A valid hex string must be provided!", nameof(hex));
        }
        bool isStackAllocation;
        byte* input;
        if (inputSize < MemoryManager.MaxStackAllocSize)
        {
            byte* b = stackalloc byte[inputSize];
            input = b;
            isStackAllocation = true;
        }
        else
        {
            input = (byte*)MemoryManager.Malloc(inputSize);
            isStackAllocation = false;
        }
        Span<byte> inputBuffer = new(input, inputSize);
        Encoding.ASCII.GetBytes(hex, inputBuffer);

        int outputSize = inputSize / 2;
        byte[] outputBuffer = new byte[outputSize];
        fixed(byte* output = outputBuffer)
        {
            HexConverter__EffectiveArch.DispatchUnhexlify(input, inputSize, output);
        }
        if (!isStackAllocation)
        {
            MemoryManager.Free(input);
        }
        return outputBuffer;
    }

    public static void Unhexlify(byte* input, Size_T inputSize, byte* output, Size_T outputSize)
    {
        // performance-happy fast path
        if (inputSize > 0 && inputSize % 2 == 0 && outputSize >= inputSize / 2)
        {
            HexConverter__EffectiveArch.DispatchUnhexlify(input, inputSize, output);
            return;
        }
        if (inputSize == 0)
        {
            return;
        }
        if (inputSize % 2 == 1)
        {
            ThrowInvalidHexInput();
        }
        else
        {
            ThrowOutputTooSmall();
        }
    }

    public static string Hexlify(byte[] input)
    {
        fixed (byte* b =  input)
        {
            return Hexlify(b, input.Length);
        }
    }

    public static string Hexlify(byte* input, Size_T inputSize)
    {
        byte* buffer = (byte*)MemoryManager.Malloc(inputSize * 2);
        byte* output = buffer;
        for (Size_T remaining = inputSize; remaining >= sizeof(uint); remaining -= sizeof(uint), input += sizeof(uint), output += sizeof(ulong))
        {
            // 00 00 00 00 67 45 23 01
            ulong input4 = *(uint*)input;
            // 00 00 00 00 76 54 32 10
            ulong y = ((input4 & 0xF0F0F0F0_F0F0F0F0uL) >> 4) | ((input4 & 0x0F0F0F0F_0F0F0F0FuL) << 4);
            // 76 00 32 00 54 00 10 00
            y = ((y & 0xFF00FF00) << 32) | (((uint)y << 8) & 0xFF00FF00);
            // 70 60 30 20 50 40 10 00
            y = ((y & 0x0F0F0F0F_0F0F0F0FuL) >> 4) | (y & 0xF0F0F0F0_F0F0F0F0uL);
            // 07 06 03 02 05 04 01 00
            y >>= 4;
            // 07 06 05 04 03 02 01 00
            uint* yMiddle = (uint*)((byte*)&y + 2);
            *yMiddle = (*yMiddle >> 16) | (*yMiddle << 16);
            // Ok
            // byte abcd_efgh: greater9 <==> e & (f | g), greater9 in {0, 1} per byte
            ulong flags8 = (y >>> 3) & ((y >>> 2) | (y >>> 1)) & 0x01010101_01010101uL;
            // basically -greater9Flags
            ulong mask8 = (~flags8 & 0x7F7F7F7F_7F7F7F7FuL) + 0x01010101_01010101uL;
            ulong upperNibble8 = 0x30303030_30303030uL ^ (mask8 & 0x70707070_70707070uL);
            *(ulong*)output = upperNibble8 | (y - (0x09090909_09090909uL & mask8));
        }
        // TODO...
        string result = Encoding.ASCII.GetString(buffer, inputSize * 2);
        MemoryManager.Free(buffer);
        return result;
    }

    [StackTraceHidden]
    [DoesNotReturn]
    private static void ThrowInvalidHexInput() => 
        throw new ArgumentException("A valid hex string must be provided!", "input");

    [StackTraceHidden]
    [DoesNotReturn]
    private static void ThrowOutputTooSmall() =>
        throw new ArgumentOutOfRangeException("outputSize", "output buffer is too small!");
}
