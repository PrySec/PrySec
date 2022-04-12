using System.Runtime.CompilerServices;

namespace PrySec.Core.HwPrimitives;

public static unsafe partial class BinaryUtils
{
    private static class BitManipulation_Defaults
    {
        /// <inheritdoc cref="BinaryUtils.BitScanReverse(int*, uint)"/>
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static int BitScanReverse(int* index, uint mask)
        {
            int idx = 0;
            if ((mask & 0xffff0000u) != 0u) { mask >>= 16; idx += 16; }
            if ((mask & 0x0000ff00u) != 0u) { mask >>= 8; idx += 8; }
            if ((mask & 0x000000f0u) != 0u) { mask >>= 4; idx += 4; }
            if ((mask & 0x0000000cu) != 0u) { mask >>= 2; idx += 2; }
            if ((mask & 0x00000002u) != 0u) { idx += 1; }
            if (mask == 0u)
            {
                return 0;
            }
            *index = idx;
            return idx + 1;
        }

        /// <inheritdoc cref="BinaryUtils.BitScanReverse(int*, ulong)"/>
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static int BitScanReverse64(int* index, ulong mask)
        {
            int idx = 0;
            if ((mask & 0xffffffff00000000uL) != 0uL) { mask >>= 32; idx += 32; }
            if ((mask & 0x00000000ffff0000uL) != 0uL) { mask >>= 16; idx += 16; }
            if ((mask & 0x000000000000ff00uL) != 0uL) { mask >>= 8; idx += 8; }
            if ((mask & 0x00000000000000f0uL) != 0uL) { mask >>= 4; idx += 4; }
            if ((mask & 0x000000000000000cuL) != 0uL) { mask >>= 2; idx += 2; }
            if ((mask & 0x0000000000000002uL) != 0uL) { idx += 1; }
            if (mask == 0uL)
            {
                return 0;
            }
            *index = idx;
            return idx + 1;
        }

        /// <inheritdoc cref="BinaryUtils.PopulationCount(uint)"/>
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static int PopulationCount(uint mask)
        {
            // reuse input as temporary
            mask -= (mask >> 1) & 0x55555555u;
            
            // temp
            mask = (mask & 0x33333333u) + ((mask >> 2) & 0x33333333u);
            
            // count
            return (int)(((mask + (mask >> 4) & 0xF0F0F0Fu) * 0x1010101u) >> 24); 
        }

        /// <inheritdoc cref="BinaryUtils.PopulationCount(ulong)"/>
        [MethodImpl(MethodImplOptions.AggressiveOptimization)]
        public static int PopulationCount64(ulong mask)
        {
            mask -= (mask >> 1) & 0x5555555555555555uL;
            mask = (mask & 0x3333333333333333uL) + ((mask >> 2) & 0x3333333333333333uL);
            return (int)((((mask + (mask >> 4)) & 0xF0F0F0F0F0F0F0FuL) * 0x101010101010101uL) >> 56);
        }
    }
}
