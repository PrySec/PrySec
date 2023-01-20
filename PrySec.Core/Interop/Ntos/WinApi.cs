using System.Runtime.InteropServices;

namespace PrySec.Core.Interop.Ntos;

public static partial class WinApi
{
    [LibraryImport("Kernel32.dll")]
    public static partial int GetLastError();
}
