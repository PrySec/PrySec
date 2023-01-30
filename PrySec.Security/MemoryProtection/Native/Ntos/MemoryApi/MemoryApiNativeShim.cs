using PrySec.Core.NativeTypes;
using System;
using System.ComponentModel;
using System.Drawing;
using System.Runtime.InteropServices;

namespace PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;

internal static unsafe partial class MemoryApiNativeShim
{
    public static int PageSize => Environment.SystemPageSize;

    public static MemoryProtection VirtualQuery(nint handle, Size_T size)
    {
        nint hInfo = IntPtr.Zero;
        try
        {
            hInfo = Marshal.AllocHGlobal(Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
            MEMORY_BASIC_INFORMATION* pInfo = (MEMORY_BASIC_INFORMATION*)hInfo;
            nuint bytesWritten = VirtualQueryNative(handle, hInfo, size);
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

    public static MemoryProtection VirtualQuery(nint handle, Size_T size, MEMORY_BASIC_INFORMATION* pBuffer)
    {
        nuint bytesWritten = VirtualQueryNative(handle, new nint(pBuffer), size);
        if (bytesWritten == 0)
        {
            int errCode = Marshal.GetLastPInvokeError();
            throw new Win32Exception(errCode);
        }
        return pBuffer->Protect;
    }

    public static MemoryProtection QueryPageInfo(nint handle, MEMORY_BASIC_INFORMATION* pBuffer) => VirtualQuery(handle, PageSize, pBuffer);

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
