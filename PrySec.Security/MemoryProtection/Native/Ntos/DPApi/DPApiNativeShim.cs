using PrySec.Core.Interop.Ntos;
using PrySec.Core.NativeTypes;
using System.ComponentModel;

namespace PrySec.Security.MemoryProtection.Native.Ntos.DPApi;

internal static partial class DPApiNativeShim
{
    public static unsafe void CryptProtectMemory(nint handle, uint count)
    {
        if (!CryptProtectMemoryNative(handle, count, CRYPTPROTECTMEMORY_SAME_PROCESS))
        {
            int errorCode = WinApi.GetLastError();
            throw new Win32Exception(errorCode);
        }
    }

    public static unsafe void CryptUnprotectMemory(nint handle, uint count)
    {
        if (!CryptUnprotectMemoryNative(handle, count, CRYPTPROTECTMEMORY_SAME_PROCESS))
        {
            int errorCode = WinApi.GetLastError();
            throw new Win32Exception(errorCode);
        }
    }

    public static Size_T RoundToNextBlockSize(Size_T size)
    {
        // CRYPTPROTECTMEMORY_BLOCK_SIZE is 16
        nuint s = size;
        nuint remainder = s & 0xF;
        return s - remainder + (CRYPTPROTECTMEMORY_BLOCK_SIZE & (nuint)((-(nint)remainder) >> ((nint.Size * 8) - 1)));
    }
}