using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace PrySec.Core.HwPrimitives;

public static unsafe partial class BinaryUtils
{
    private static class BitManipulationIntrinsics_Abm
    {
        /// <inheritdoc cref="BinaryUtils.BitScanReverse(int*, uint)"/>
        /// <remarks>Requires <see cref="Lzcnt"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static int BitScanReverse(int* index, uint mask)
        {
            int leadingZeros = (int)Lzcnt.LeadingZeroCount(mask);
            *index = 31 - leadingZeros;
            
            // return nonzero if index was set, or 0 if no set bits were found.
            return 32 - leadingZeros;
        }

        /// <inheritdoc cref="BinaryUtils.PopulationCount(uint)"/>
        /// <remarks>Requires <see cref="Popcnt"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static int PopulationCount(uint mask) => (int)Popcnt.PopCount(mask);
    }

    private static class BitManipulationIntrinsics_AbmX64
    {
        /// <inheritdoc cref="BinaryUtils.BitScanReverse(int*, ulong)"/>
        /// <remarks>Requires <see cref="Lzcnt.X64"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static int BitScanReverse(int* index, ulong mask)
        {
            int leadingZeros = (int)Lzcnt.X64.LeadingZeroCount(mask);
            *index = 63 - leadingZeros;
            
            // return nonzero if index was set, or 0 if no set bits were found.
            return 64 - leadingZeros;
        }

        /// <inheritdoc cref="BinaryUtils.PopulationCount(ulong)"/>
        /// <remarks>Requires <see cref="Popcnt.X64"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static int PopulationCount(ulong mask) => (int)Popcnt.X64.PopCount(mask);
    }
}
