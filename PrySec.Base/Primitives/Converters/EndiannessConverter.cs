namespace PrySec.Base.Primitives.Converters
{
    public static class EndiannessConverter
    {
        public static ushort Swap(ushort u) =>
            (ushort)(((u & 0xFF00u) >> 8) |
            ((u & 0x00FFu) << 8));

        public static uint Swap(uint u) =>
            ((u & 0xFF00_0000u) >> 24) |
            ((u & 0x00FF_0000u) >> 8) |
            ((u & 0x0000_FF00u) << 8) |
            ((u & 0x0000_00FFu) << 24);

        public static ulong Swap(ulong u) =>
            ((u & 0xFF000000_00000000ul) >> 56) |
            ((u & 0x00FF0000_00000000ul) >> 40) |
            ((u & 0x0000FF00_00000000ul) >> 24) |
            ((u & 0x000000FF_00000000ul) >> 8) |
            ((u & 0x00000000_FF000000ul) << 8) |
            ((u & 0x00000000_00FF0000ul) << 24) |
            ((u & 0x00000000_0000FF00ul) << 40) |
            ((u & 0x00000000_000000FFul) << 56);

        public static unsafe long Swap(long s)
        {
            ulong result = Swap(*(ulong*)&s);
            return *(long*)&result;
        }

        public static unsafe int Swap(int s)
        {
            ulong result = Swap(*(uint*)&s);
            return *(int*)&result;
        }

        public static unsafe short Swap(short s)
        {
            ushort result = Swap(*(ushort*)&s);
            return *(short*)&result;
        }
    }
}
