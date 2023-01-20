using System;
using System.Runtime.InteropServices;

namespace PrySec.Security.MemoryProtection.Native.Ntos;

static partial class DPApiNativeShim
{
    private const uint CRYPTPROTECTMEMORY_BLOCK_SIZE = 16;

    /// <summary>
    /// Encrypt and decrypt memory in the same process. An application running in a different process will not be able to decrypt the data.
    /// </summary>
    private const uint CRYPTPROTECTMEMORY_SAME_PROCESS = 0x0;

    /// <summary>
    /// Encrypt and decrypt memory in different processes. An application running in a different process will be able to decrypt the data.
    /// </summary>
    private const uint CRYPTPROTECTMEMORY_CROSS_PROCESS = 0x1;

    /// <summary>
    /// Use the same logon credentials to encrypt and decrypt memory in different processes. An application running in a different process will be able to decrypt the data. However, the process must run as the same user that encrypted the data and in the same logon session.
    /// </summary>
    private const uint CRYPTPROTECTMEMORY_SAME_LOGON = 0x2;

    [LibraryImport("Crypt32.dll", SetLastError = true, EntryPoint = "CryptProtectMemory")]
    [return: MarshalAs(UnmanagedType.I4)]
    private static partial bool CryptProtectMemoryNative(nint pDataIn, uint cbDataIn, uint dwFlags);

    [LibraryImport("Crypt32.dll", SetLastError = true, EntryPoint = "CryptUnprotectMemory")]
    [return: MarshalAs(UnmanagedType.I4)]
    private static partial bool CryptUnprotectMemoryNative(nint pDataIn, uint cbDataIn, uint dwFlags);
}