using System;
using System.Reflection;
using System.Runtime.InteropServices;

namespace PrySec.Core.Interop.Ntos;

public static partial class WinApi
{
    public static int GetLastError() => 
        Marshal.GetLastWin32Error();
}
