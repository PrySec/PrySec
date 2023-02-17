using System.Text;
using PrySec.Core.NativeTypes;

namespace PrySec.Core.Native.UnixLike.Procfs;

public unsafe struct ProcfsMemoryRegionInfo
{
    public nint RegionStartAddress;
    public nint RegionEndAddress;
    public Size_T RegionSize;
    public ProcfsPermissions Permissions;
    public nuint Offset;
    public ProcfsDevice Device;
    public nint Inode;
    public byte* Path;
    public int PathLength;

    public readonly string? ReadPath() =>
        Path == null
            ? null
            : Encoding.ASCII.GetString(Path, PathLength);

    public override readonly string ToString() => 
        $"0x{RegionStartAddress:x16}-0x{RegionEndAddress:x16} ({RegionSize} bytes) {Permissions} {Offset} {Device} {Inode} {ReadPath() ?? string.Empty}";
}
