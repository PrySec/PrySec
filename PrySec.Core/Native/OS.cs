using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace PrySec.Core.Native;

public static class OS
{
    public static Size_T PageSize { get; } = Environment.SystemPageSize;

    public static Size_T RoundToNextPageSize(Size_T size)
    {
        nuint s = size;
        nuint pageSize = PageSize;
        nuint remainder = s % pageSize;
        return s - remainder + (pageSize & (nuint)((-(nint)remainder) >> ((nint.Size * 8) - 1)));
    }

    private static OSPlatform? _currentPlatform;

    public static OSPlatform GetCurrentPlatform() => _currentPlatform ??= 0 switch
    {
        _ when RuntimeInformation.IsOSPlatform(OSPlatform.Windows) => OSPlatform.Windows,
        _ when RuntimeInformation.IsOSPlatform(OSPlatform.Linux) => OSPlatform.Linux,
        _ when RuntimeInformation.IsOSPlatform(OSPlatform.OSX) => OSPlatform.OSX,
        _ when RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD) => OSPlatform.FreeBSD,
        _ => throw new PlatformNotSupportedException()
    };

    public static bool IsPlatform(OSPlatform platform) => RuntimeInformation.IsOSPlatform(platform);
}
