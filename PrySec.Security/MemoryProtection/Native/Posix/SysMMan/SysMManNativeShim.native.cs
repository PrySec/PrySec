using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.MemoryProtection.Native.Posix.SysMMan;

internal static unsafe partial class SysMManNativeShim
{
    [LibraryImport("libc", EntryPoint = "mprotect", SetLastError = true)]
    private static partial int MProtectNative(nint addr, int len, int prot);

    [LibraryImport("libc", EntryPoint = "mlock", SetLastError = true)]
    private static partial int MLockNative(nint addr, int len);

    [LibraryImport("libc", EntryPoint = "munlock", SetLastError = true)]
    private static partial int MUnlockNative(nint addr, int len);
}

internal enum MemoryProtection : int
{
    /// <summary>
    /// no permissions
    /// </summary>
    PROT_NONE = 0x00,

    /// <summary>
    /// pages can be read
    /// </summary>
    PROT_READ = 0x01,

    /// <summary>
    /// pages can be written
    /// </summary>
    PROT_WRITE = 0x02,

    /// <summary>
    /// pages can be executed
    /// </summary>
    PROT_EXEC = 0x04,
}