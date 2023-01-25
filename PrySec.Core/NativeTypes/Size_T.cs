using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Core.NativeTypes;

[StructLayout(LayoutKind.Explicit)]
public unsafe readonly struct Size_T
{
    [FieldOffset(0x0)]
    private readonly nuint value;

    private Size_T(nuint value) => this.value = value;

    public static implicit operator uint(Size_T size) => (uint)size.value;

    public static implicit operator int(Size_T size) => (int)size.value;

    public static implicit operator ulong(Size_T size) => size.value;

    public static implicit operator nuint(Size_T size) => size.value;

    public static implicit operator Size_T(int i) => new((nuint)i);

    public static implicit operator Size_T(uint i) => new(i);

    public static implicit operator Size_T(nuint i) => new(i);

    public static explicit operator IntPtr(Size_T size) => new(size);
    
    public static explicit operator byte(Size_T size) => (byte)size.value;

    public static Size_T operator *(Size_T a, Size_T b) => new(a.value * b.value);

    public static bool operator <(Size_T a, Size_T b) => a.value < b.value;

    public static bool operator >(Size_T a, Size_T b) => a.value > b.value;

    public static bool operator ==(Size_T a, Size_T b) => a.value == b.value;

    public static bool operator !=(Size_T a, Size_T b) => a.value != b.value;

    public override bool Equals(object? obj) => obj is Size_T t && value.Equals(t.value);

    public override int GetHashCode() => value.GetHashCode();

    public static readonly int ByteSize = sizeof(nint);

    public static readonly int BitSize = sizeof(nint) << 3;
}