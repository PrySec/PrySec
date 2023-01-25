using PrySec.Core.NativeTypes;

namespace PrySec.Security.MemoryProtection.Portable.Sentinels;
public static unsafe class DeterministicSentinel
{
    public static DeterministicSentinel<T> Protect<T>(T* target, Size_T elementCount) where T : unmanaged => new(target, elementCount);
}
