using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.MemoryProtection.Universal;
public static unsafe class DeterministicSpan
{
    public static DeterministicSpan<T> ProtectSingle<T>(T* target) where T : unmanaged =>
        DeterministicSpan<T>.ProtectOnly(target, sizeof(T));

    public static DeterministicSpan<T> ProtectOnly<T>(T* target, Size_T byteSize) where T : unmanaged =>
        DeterministicSpan<T>.ProtectOnly(target, byteSize);
}
