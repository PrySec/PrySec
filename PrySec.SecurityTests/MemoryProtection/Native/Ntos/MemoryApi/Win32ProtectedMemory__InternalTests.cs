using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Security.MemoryProtection.Portable.ProtectedMemory;
using PrySec.SecurityTests;
using System.Runtime.InteropServices;

namespace PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi.Tests;

#if WIN32

[TestClass]
public unsafe class Win32ProtectedMemory__InternalTests : BaseTest
{
    static Win32ProtectedMemory__InternalTests()
    {
        // watchdog exceptions will crash the host test process...
        // prevent watchdogs from starting
        PageProtectionStateWatchdog._isRunning = PageProtectionStateWatchdog.TRUE;
        // disable access detection
        PageProtectionStateWatchdog._failed = PageProtectionStateWatchdog.TRUE;
    }

    [TestMethod]
    public void QueryPageInfoTestFrontGuard()
    {
        MEMORY_BASIC_INFORMATION* pInfo = (MEMORY_BASIC_INFORMATION*)MemoryManager.Malloc(Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
        using Win32ProtectedMemory__Internal<byte> mem = Win32ProtectedMemory__Internal<byte>.Allocate(128);
        MemoryProtection frontGuardInfo = MemoryApiNativeShim.QueryPageInfo(mem.FrontGuardHandle, pInfo);
        Assert.AreEqual(MemoryProtection.PAGE_READONLY | MemoryProtection.PAGE_GUARD, frontGuardInfo);
        Assert.ThrowsException<SEHException>(() => *(byte*)mem.FrontGuardHandle);
        MemoryProtection violatedFrontGuardInfo = MemoryApiNativeShim.QueryPageInfo(mem.FrontGuardHandle, pInfo);
        Assert.AreEqual(MemoryProtection.PAGE_READONLY, violatedFrontGuardInfo);
        MemoryManager.Free(pInfo);
    }

    [TestMethod]
    public void QueryPageInfoTestRearGuard()
    {
        MEMORY_BASIC_INFORMATION* pInfo = (MEMORY_BASIC_INFORMATION*)MemoryManager.Malloc(Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
        using Win32ProtectedMemory__Internal<byte> mem = Win32ProtectedMemory__Internal<byte>.Allocate(128);
        MemoryProtection rearGuardInfo = MemoryApiNativeShim.QueryPageInfo(mem.RearGuardHandle, pInfo);
        Assert.AreEqual(MemoryProtection.PAGE_READONLY | MemoryProtection.PAGE_GUARD, rearGuardInfo);
        Assert.ThrowsException<SEHException>(() => *(byte*)mem.RearGuardHandle);
        MemoryProtection violatedRearGuardInfo = MemoryApiNativeShim.QueryPageInfo(mem.RearGuardHandle, pInfo);
        Assert.AreEqual(MemoryProtection.PAGE_READONLY, violatedRearGuardInfo);
        MemoryManager.Free(pInfo);
    }

    [TestMethod]
    public void QueryPageInfoTestNoAccess()
    {
        MEMORY_BASIC_INFORMATION* pInfo = (MEMORY_BASIC_INFORMATION*)MemoryManager.Malloc(Marshal.SizeOf<MEMORY_BASIC_INFORMATION>());
        using Win32ProtectedMemory__Internal<byte> mem = Win32ProtectedMemory__Internal<byte>.Allocate(128);
        MemoryProtection baseGuardInfo = MemoryApiNativeShim.QueryPageInfo(mem.BaseHandle, pInfo);
        Assert.AreEqual(MemoryProtection.PAGE_NOACCESS, baseGuardInfo);
        using (IMemoryAccess<byte> access = mem.GetAccess())
        {
            MemoryProtection allowedBaseGuardInfo = MemoryApiNativeShim.QueryPageInfo(mem.BaseHandle, pInfo);
            Assert.AreEqual(MemoryProtection.PAGE_READWRITE, allowedBaseGuardInfo);
            *access.Pointer = 0;
        }
        baseGuardInfo = MemoryApiNativeShim.QueryPageInfo(mem.BaseHandle, pInfo);
        Assert.AreEqual(MemoryProtection.PAGE_NOACCESS, baseGuardInfo);
        MemoryManager.Free(pInfo);
    }
}

#endif