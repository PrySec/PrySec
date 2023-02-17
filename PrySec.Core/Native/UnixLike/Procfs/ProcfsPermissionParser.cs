using System.Runtime.CompilerServices;

namespace PrySec.Core.Native.UnixLike.Procfs;

public static class ProcfsPermissionParser
{
    private const uint PERM_READ = 'r' << 24;
    private const uint PERM_WRITE = 'w' << 16;
    private const uint PERM_EXEC = 'x' << 8;
    private const uint PERM_SHRD = 's' << 0;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static ProcfsPermissions Parse(uint data) =>
        ProcfsPermissions.NoAccess
        | (ProcfsPermissions)(~(-(int)(data & PERM_READ ^ PERM_READ) >> 31) & (int)ProcfsPermissions.Read)
        | (ProcfsPermissions)(~(-(int)(data & PERM_WRITE ^ PERM_WRITE) >> 31) & (int)ProcfsPermissions.Write)
        | (ProcfsPermissions)(~(-(int)(data & PERM_EXEC ^ PERM_EXEC) >> 31) & (int)ProcfsPermissions.Execute)
        | (ProcfsPermissions)(~(-(int)(data & PERM_SHRD ^ PERM_SHRD) >> 31) & (int)ProcfsPermissions.Shared);
}
