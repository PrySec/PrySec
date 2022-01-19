using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Core.Primitives.Converters
{
    public static class TypeConverter
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        public static unsafe TTo UnsafeCast<TFrom, TTo>(TFrom value) where TFrom : unmanaged where TTo : unmanaged =>
            *(TTo*)&value;
    }
}
