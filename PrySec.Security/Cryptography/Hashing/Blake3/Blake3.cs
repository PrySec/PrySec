using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Portable;
using PrySec.Security.MemoryProtection.Portable.Sentinels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Blake3;

public unsafe partial class Blake3 : IHashFunctionScp
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<T>(ref IUnmanaged<T> input) where T : unmanaged =>
        ComputeHash<T, IUnmanaged<T>, DeterministicMemory<byte>>(ref input);

    public TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
    {
        Blake3Context context = default;
        using DeterministicSentinel<Blake3Context> _ = DeterministicSentinel.Protect(&context);
        Blake3Context.Initialize(&context);
        using (IMemoryAccess<byte> access = input.GetAccess<byte>())
        {
            Blake3Context.Update(&context, access.Pointer, access.ByteSize);
        }
        TOutputMemory output = TOutputMemory.Allocate(BLAKE3_OUT_LEN);
        using (IMemoryAccess<byte> access = output.GetAccess())
        {
            Blake3Context.Finalize(&context, access.Pointer, access.ByteSize);
        }
        return output;
    }
}
