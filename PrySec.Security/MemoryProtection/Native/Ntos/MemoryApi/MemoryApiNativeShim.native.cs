using System;
using System.Runtime.InteropServices;

namespace PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;
internal static partial class MemoryApiNativeShim
{
    [LibraryImport("kernel32.dll", EntryPoint = "VirtualProtect", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualProtectNative(nint lpAddress, nuint dwSize, uint flNewProtect, out uint lpflOldProtect);

    [LibraryImport("kernel32.dll", EntryPoint = "VirtualLock", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualLockNative(nint lpAddress, nuint dwSize);

    [LibraryImport("kernel32.dll", EntryPoint = "VirtualUnlock", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static partial bool VirtualUnlockNative(nint lpAddress, nuint dwSize);

    [LibraryImport("kernel32.dll", EntryPoint = "VirtualQuery", SetLastError = true)]
    private static partial nuint VirtualQueryNative(nint lpAddress, nint lpBuffer, uint dwLength);
}

internal enum MemoryProtection : uint
{
    FAILURE = 0,
    PAGE_EXECUTE = 0x10,
    PAGE_EXECUTE_READ = 0x20,
    PAGE_EXECUTE_READWRITE = 0x40,
    PAGE_EXECUTE_WRITECOPY = 0x80,
    PAGE_NOACCESS = 0x01,
    PAGE_READONLY = 0x02,
    PAGE_READWRITE = 0x04,
    PAGE_WRITECOPY = 0x08,
    PAGE_TARGETS_INVALID = 0x40000000,
    PAGE_TARGETS_NO_UPDATE = PAGE_TARGETS_INVALID,
    PAGE_GUARD = 0x100,
    PAGE_NOCACHE = 0x200,
    PAGE_WRITECOMBINE = 0x400
}

[StructLayout(LayoutKind.Sequential)]
internal struct MEMORY_BASIC_INFORMATION
{
    public UIntPtr BaseAddress;
    public UIntPtr AllocationBase;
    public uint AllocationProtect;
    public IntPtr RegionSize;
    public uint State;
    public MemoryProtection Protect;
    public uint Type;
}