using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Base
{
    public static class Pointer
    {
        public static readonly unsafe void* NULL = (void*)0x0;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static unsafe T* NullOf<T>() where T : unmanaged => (T*)NULL;
    }
}
