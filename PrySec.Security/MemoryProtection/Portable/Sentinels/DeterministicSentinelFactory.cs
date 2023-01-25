using PrySec.Core.NativeTypes;
using System.Runtime.CompilerServices;

namespace PrySec.Security.MemoryProtection.Portable.Sentinels;
public static unsafe class DeterministicSentinel
{
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static DeterministicSentinel<T> Protect<T>(T* target) where T : unmanaged => new(target);
}
