using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace PrySec.Core.HwPrimitives;

public static unsafe partial class BinaryUtils
{
    private static class BitManipulationIntrinsics_Arm
    {
        /// <inheritdoc cref="BinaryUtils.BitScanReverse(int*, uint)"/>
        /// <remarks>Requires <see cref="ArmBase"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static int BitScanReverse(int* index, uint mask)
        {
            int leadingZeros = ArmBase.LeadingZeroCount(mask);
            *index = 31 - leadingZeros;
            
            // return nonzero if index was set, or 0 if no set bits were found.
            return 32 - leadingZeros;
        }
    }

    private static class BitManipulationIntrinsics_AdvSimd
    {
        /// <inheritdoc cref="BinaryUtils.PopulationCount(uint)"/>
        /// <remarks>Requires <see cref="AdvSimd"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static int PopulationCount(uint mask) =>
            (int)AdvSimd.AddPairwiseWidening(
                    AdvSimd.AddPairwiseWidening(
                        AdvSimd.PopCount(
                            Vector64.CreateScalar(mask).AsByte())))
            .ToScalar();

        /// <inheritdoc cref="BinaryUtils.PopulationCount(ulong)"/>
        /// <remarks>Requires <see cref="AdvSimd"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static int PopulationCount64(ulong mask) =>
            (int)AdvSimd.AddPairwiseWideningScalar(
                AdvSimd.AddPairwiseWidening(
                    AdvSimd.AddPairwiseWidening(
                        AdvSimd.PopCount(
                            AdvSimd.LoadVector64((byte*)&mask)))))
            .ToScalar();
    }

    private static class BitManipulationIntrinsics_Arm64
    {
        /// <inheritdoc cref="BinaryUtils.BitScanReverse(int*, ulong)"/>
        /// <remarks>Requires <see cref="ArmBase.Arm64"/>.</remarks>
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static int BitScanReverse(int* index, ulong mask)
        {
            int leadingZeros = ArmBase.Arm64.LeadingZeroCount(mask);
            *index = 63 - leadingZeros;
            
            // return nonzero if index was set, or 0 if no set bits were found.
            return 64 - leadingZeros;
        }
    }
}
