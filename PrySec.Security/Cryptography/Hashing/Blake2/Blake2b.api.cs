using PrySec.Core.Memory;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Blake2;

public partial class Blake2b
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<T>(ref IUnmanaged<T> input) where T : unmanaged =>
        ComputeHash<T, IUnmanaged<T>, DeterministicSpan<byte>>(ref input, 32);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<TInput, TInputMemory, TOutputMemory>(ref TInputMemory input, ref TInputMemory key)
        where TInputMemory : IUnmanaged<TInput>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
        where TInput : unmanaged =>
        ComputeHash<TInput, TInput, TInputMemory, TInputMemory, TOutputMemory>(ref input, ref key, 32);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<TInput, TInputMemory, TOutputMemory>(ref TInputMemory input, ref TInputMemory key, Size32_T digestLength)
        where TInputMemory : IUnmanaged<TInput>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
        where TInput : unmanaged =>
        ComputeHash<TInput, TInput, TInputMemory, TInputMemory, TOutputMemory>(ref input, ref key, digestLength);

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<TData, TKey, TDataInputMemory, TKeyInputMemory, TOutputMemory>(ref TDataInputMemory input, ref TKeyInputMemory key)
        where TDataInputMemory : IUnmanaged<TData>
        where TKeyInputMemory : IUnmanaged<TKey>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
        where TData : unmanaged
        where TKey : unmanaged =>
        ComputeHash<TData, TKey, TDataInputMemory, TKeyInputMemory, TOutputMemory>(ref input, ref key, 32);
}
