using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Core.Primitives.Converters.Hex.Intrinsics;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
            HexConverter__EffectiveArch.DispatchUnhexlify(input, inputSize, output, outputSize);
        }
        if (!isStackAllocation)
        {
            MemoryManager.Free(input);
        }
        return outputBuffer;
    }
}
