using PrySec.Core.NativeTypes;
using System;
using System.ComponentModel;
using System.Drawing;
using System.Runtime.InteropServices;

namespace PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;

internal static unsafe partial class MemoryApiNativeShim
{
    public static int PageSize => Environment.SystemPageSize;

    public static MemoryProtection VirtualQuery(void* ptr, Size_T size)
    {
        nint hInfo = IntPtr.Zero;
        try
        {
            hInfo = Marshal.AllocHGlobal(Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
            MEMORY_BASIC_INFORMATION* pInfo = (MEMORY_BASIC_INFORMATION*)hInfo;
            nuint bytesWritten = VirtualQueryNative(new nint(ptr), hInfo, size);
            if (bytesWritten == 0)
            {
                int errCode = Marshal.GetLastPInvokeError();
                throw new Win32Exception(errCode);
            }
            return pInfo->Protect;
        }
        finally
        {
            Marshal.FreeHGlobal(hInfo);
        }
    }

    public static void VirtualProtect(nint handle, Size_T size, MemoryProtection protection)
    {
        if (!VirtualProtectNative(handle, size, (uint)protection, out _))
        {
            int lastError = Marshal.GetLastPInvokeError();
            throw new Win32Exception(lastError);
        }
    }

    public static void VirtualLock(nint handle, Size_T size)
    {
        if (!VirtualLockNative(handle, size))
        {
            int lastError = Marshal.GetLastPInvokeError();
            throw new Win32Exception(lastError);
        }
    }

    public static void VirtualUnlock(nint handle, Size_T size)
    {
        if (!VirtualLockNative(handle, size))
        {
            int lastError = Marshal.GetLastPInvokeError();
            throw new Win32Exception(lastError);
        }
    }

    public static Size_T RoundToNextPageSize(Size_T size)
    {
        nuint s = size;
        nuint pageSize = (nuint)PageSize;
        nuint remainder = s % pageSize;
        return s - remainder + (pageSize & (nuint)((-(nint)remainder) >> ((nint.Size * 8) - 1)));
    }
}
