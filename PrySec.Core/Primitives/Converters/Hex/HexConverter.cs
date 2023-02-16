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
        if (inputSize % 2 == 0 && outputSize >= inputSize / 2)
        {
            HexConverter__EffectiveArch.DispatchUnhexlify(input, inputSize, output);
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
        HexConverter__EffectiveArch.DispatchUnhexlify(input, inputSize, output);
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
