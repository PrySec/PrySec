using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.MemoryProtection.Universal;
public static unsafe class DeterministicMemory
{
    public static DeterministicMemory<T> ProtectSingle<T>(T* target) where T : unmanaged =>
        DeterministicMemory<T>.ProtectOnly(target, sizeof(T));

    public static DeterministicMemory<T> ProtectOnly<T>(T* target, Size_T byteSize) where T : unmanaged =>
        DeterministicMemory<T>.ProtectOnly(target, byteSize);
}
