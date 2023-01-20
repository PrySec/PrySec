using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.MemoryProtection.Portable.Sentinels;
public static unsafe class DeterministicSentinel
{
    public static DeterministicSentinel<T> Protect<T>(T* target) where T : unmanaged => new(target, sizeof(T));
}
