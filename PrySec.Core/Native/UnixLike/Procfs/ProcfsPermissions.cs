using System;

namespace PrySec.Core.Native.UnixLike.Procfs;

[Flags]
public enum ProcfsPermissions : int
{
    NoAccess = 0x0,
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
    Shared = 0x8,
}
