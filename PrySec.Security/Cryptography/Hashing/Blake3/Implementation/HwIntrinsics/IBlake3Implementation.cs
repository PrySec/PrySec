﻿using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Blake3;

public unsafe partial class Blake3
{
    private interface IBlake3Implementation
    {
        static abstract void CompressInPlace(uint* cv, byte* block, uint blockLength, ulong counter, Blake3Flags flags);
        
        static abstract void HashMany(byte** inputs, ulong inputCount, uint blockCount, uint* key, ulong counter, bool incrementCounter, Blake3Flags flags, Blake3Flags flagsStart, Blake3Flags flagsEnd, byte* output);

        static abstract void CompressXof(uint* cv, byte* block, uint blockLength, ulong counter, Blake3Flags flags, byte* output);

        static abstract uint SimdDegree { get; }
    }
}
