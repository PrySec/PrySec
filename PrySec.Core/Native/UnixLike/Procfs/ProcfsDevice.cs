namespace PrySec.Core.Native.UnixLike.Procfs;

public readonly struct ProcfsDevice
{
    public readonly byte Major;
    public readonly byte Minor;

    public ProcfsDevice(byte major, byte minor)
    {
        Major = major;
        Minor = minor;
    }

    public override string ToString() => $"{Major:x2}:{Minor:x2}";
}