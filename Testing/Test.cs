using BenchmarkDotNet.Attributes;
using System;
using PrySec.Core.Primitives.Converters;
using PrySec.Core.NativeTypes;
using System.Text;
using PrySec.Core.Memory.MemoryManagement;

namespace Testing;

public unsafe class Test
{
    private readonly string input;

    private readonly byte* pInput;

    private readonly Size_T inputSize;

    private readonly byte* pOutput;

    private static readonly Size_T outputSize = 8192;

    public Test()
    {
        Random random = new(42);
        byte[] bytes = new byte[outputSize];
        random.NextBytes(bytes);
        input = Convert.ToHexString(bytes);
        inputSize = Encoding.ASCII.GetByteCount(input);
        pInput = (byte*)MemoryManager.Malloc(inputSize);
        pOutput = (byte*)MemoryManager.Malloc(outputSize);
    }

    [Benchmark(Baseline = true)]
    public byte[] ConvertFromHex() => Convert.FromHexString(input);

    [Benchmark]
    public void HwAccelerated() => HexConverter.Unhexlify(pInput, inputSize, pOutput, outputSize);
}