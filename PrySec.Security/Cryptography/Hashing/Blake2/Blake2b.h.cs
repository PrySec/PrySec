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

public unsafe partial class Blake2b
{
    /// <summary>
    /// Computes the hash value for the specified <paramref name="input"/>.
    /// </summary>
    /// <typeparam name="T">The type of the <paramref name="input"/>.</typeparam>
    /// <param name="input">The input to compute the hash code for.</param>
    /// <returns>The computed hash code.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<T>(ref IUnmanaged<T> input) where T : unmanaged =>
        ComputeHash<T, IUnmanaged<T>, DeterministicSpan<byte>>(ref input, 64);

    /// <summary>
    /// Computes the hash value for the specified <paramref name="input"/>.
    /// </summary>
    /// <typeparam name="TInput">The type of the <paramref name="input"/>.</typeparam>
    /// <typeparam name="TInputMemory">The type of the <paramref name="input"/> memory.</typeparam>
    /// <typeparam name="TOutputMemory">The type of the output memory.</typeparam>
    /// <param name="input">The input to compute the hash code for.</param>
    /// <param name="key">The key to compute the hash code for.</param>
    /// <returns>The computed hash code.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<TInput, TInputMemory, TOutputMemory>(ref TInputMemory input, ref TInputMemory key)
        where TInputMemory : IUnmanaged<TInput>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
        where TInput : unmanaged =>
        ComputeHash<TInput, TInput, TInputMemory, TInputMemory, TOutputMemory>(ref input, ref key, 64);

    /// <summary>
    /// Computes the hash value for the specified <paramref name="input"/>.
    /// </summary>
    /// <typeparam name="TInput">The type of the <paramref name="input"/>.</typeparam>
    /// <typeparam name="TInputMemory">The type of the <paramref name="input"/> memory.</typeparam>
    /// <typeparam name="TOutputMemory">The type of the output memory.</typeparam>
    /// <param name="input">The input to compute the hash code for.</param>
    /// <param name="key">The key to compute the hash code for.</param>
    /// <param name="digestLength">The digest length.</param>
    /// <returns>The computed hash code.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<TInput, TInputMemory, TOutputMemory>(ref TInputMemory input, ref TInputMemory key, Size32_T digestLength)
        where TInputMemory : IUnmanaged<TInput>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
        where TInput : unmanaged =>
        ComputeHash<TInput, TInput, TInputMemory, TInputMemory, TOutputMemory>(ref input, ref key, digestLength);

    /// <summary>
    /// Computes the hash value for the specified <paramref name="input"/>.
    /// </summary>
    /// <typeparam name="TData">The type of the <paramref name="input"/>.</typeparam>
    /// <typeparam name="TKey">The type of the <paramref name="key"/>.</typeparam>
    /// <typeparam name="TDataInputMemory">The type of the <paramref name="input"/> memory.</typeparam>
    /// <typeparam name="TKeyInputMemory">The type of the <paramref name="key"/> memory.</typeparam>
    /// <typeparam name="TOutputMemory">The type of the output memory.</typeparam>
    /// <param name="input">The input to compute the hash code for.</param>
    /// <param name="key">The key to compute the hash code for.</param>
    /// <returns>The computed hash code.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public IUnmanaged<byte> ComputeHash<TData, TKey, TDataInputMemory, TKeyInputMemory, TOutputMemory>(ref TDataInputMemory input, ref TKeyInputMemory key)
        where TDataInputMemory : IUnmanaged<TData>
        where TKeyInputMemory : IUnmanaged<TKey>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte>
        where TData : unmanaged
        where TKey : unmanaged =>
        ComputeHash<TData, TKey, TDataInputMemory, TKeyInputMemory, TOutputMemory>(ref input, ref key, 64);

    /// <summary>
    /// Computes the hash value for the specified <paramref name="input"/>.
    /// </summary>
    /// <typeparam name="TData">The type of the <paramref name="input"/>.</typeparam>
    /// <typeparam name="TInputMemory">The type of the <paramref name="input"/> memory.</typeparam>
    /// <typeparam name="TOutputMemory">The type of the output memory.</typeparam>
    /// <param name="input">The input to compute the hash code for.</param>
    /// <returns>The computed hash code.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public TOutputMemory ComputeHash<TData, TInputMemory, TOutputMemory>(ref TInputMemory input)
        where TData : unmanaged
        where TInputMemory : IUnmanaged<TData>
        where TOutputMemory : IUnmanaged<TOutputMemory, byte> =>
        ComputeHash<TData, TInputMemory, TOutputMemory>(ref input, 64);

    private readonly ref struct Blake2State<TInputMemory>
        where TInputMemory : IUnmanaged
    {
        public readonly TInputMemory Input;
        public readonly ulong* Hash;
        public readonly uint KeyLength;
        public readonly uint DigestLength;

        public Blake2State(TInputMemory input, ulong* hash, uint keyLength, uint digestLength)
        {
            Input = input;
            Hash = hash;
            KeyLength = keyLength;
            DigestLength = digestLength;
        }
    }

    private struct BlakeCompressionState
    {
        public readonly ulong* Hash;
        public byte* WorkVector;
        public readonly ulong* Iv;
        public byte* Input;
        public fixed ulong BytesCompressed[2];
        public ulong BytesRemaining;
        public ulong StateMask;

        public BlakeCompressionState(ulong* hash, byte* input, ulong* iv, nuint bytesRemaining)
        {
            WorkVector = null;
            Hash = hash;
            Input = input;
            Iv = iv;
            BytesRemaining = bytesRemaining;
            BytesCompressed[0] = 0;
            BytesCompressed[1] = 0;
            StateMask = (ulong)CompressionStateMask.NotLastBlock;
        }

        public static void IncrementCompressedBytes(BlakeCompressionState* state, ulong value)
        {
            state->BytesCompressed[0] += value;
            if (state->BytesCompressed[0] > value)
            {
                state->BytesCompressed[0]++;
            }
        }
    }

    private enum CompressionStateMask : ulong
    {
        NotLastBlock = 0x0UL,
        LastBlock = ~NotLastBlock,
    }

    private static readonly int[,] SIGMA_IV = new int[12,16]
    {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}
    };
}
