using System;
using System.Runtime.CompilerServices;

namespace PrySec.Core.Exceptions;

public static class ThrowHelper
{
    [MethodImpl(MethodImplOptions.NoInlining)]
    public static void ThrowInvalidCastException(string message) =>
        throw new InvalidCastException(message);
}