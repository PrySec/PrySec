using PrySec.Core.Native.Posix;
using System.Runtime.InteropServices;

namespace PrySec.Security.MemoryProtection.Native.Posix.SysMMan;
internal static unsafe partial class SysMManNativeShim
{
    public static void MProtect(nint addr, int len, MemoryProtection protection)
    {
        int status = MProtectNative(addr, len, (int)protection);
        if (status != 0)
        {
            if (status == -1)
            {
                int errno = Marshal.GetLastPInvokeError();
                throw new PosixException(errno);
            }
            throw new ExternalException($"{nameof(MProtect)} failed with status {status}.");
        }
    }

    public static void MLock(nint addr, int len)
    {
        int status = MLockNative(addr, len);
        if (status != 0)
        {
            if (status == -1)
            {
                int errno = Marshal.GetLastPInvokeError();
                throw new PosixException(errno);
            }
            throw new ExternalException($"{nameof(MLock)} failed with status {status}.");
        }
    }
    
    public static void MUnlock(nint addr, int len)
    {
        int status = MUnlockNative(addr, len);
        if (status != 0 )
        {
            if (status == -1)
            {
                int errno = Marshal.GetLastPInvokeError();
                throw new PosixException(errno);
            }
            throw new ExternalException($"{nameof(MUnlock)} failed with status {status}.");
        }
    }
}