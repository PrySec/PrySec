using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.CoreTests;
using PrySec.Core.Memory.MemoryManagement;
using System;
using PrySec.Core.NativeTypes;

namespace PrySec.Core.Native.UnixLike.Procfs.Tests;

[TestClass]
public unsafe class ProcfsMapsParserTests : BaseTest
{
    [TestMethod]
    public void VirtualQueryExTest()
    {
        if (IntPtr.Size == 8)
        {
            using ProcfsMapsParser mapsParser = new(256);
            ProcfsMemoryRegionInfo* pInfo = stackalloc ProcfsMemoryRegionInfo[1];
            nint baseAddress = unchecked((nint)0x7ffea68fd000);
            bool success = mapsParser.TryVirtualQueryEx("maps.txt", baseAddress, pInfo, true);
            Assert.IsTrue(success);
            Assert.AreEqual(baseAddress, pInfo->RegionStartAddress);
            Assert.AreEqual(0x7ffea691e000uL, (ulong)pInfo->RegionEndAddress);
            Assert.AreEqual((Size_T)135168, pInfo->RegionSize);
            Assert.AreEqual((nuint)0, pInfo->Offset);
            Assert.AreEqual(new ProcfsDevice(0, 0), pInfo->Device);
            Assert.AreEqual(0, pInfo->Inode);
            Assert.AreEqual(7, pInfo->PathLength);
            Assert.AreEqual("[stack]", pInfo->ReadPath());
            Assert.AreEqual(pInfo->Permissions, ProcfsPermissions.Read | ProcfsPermissions.Write);
            if (pInfo->Path != null)
            {
                MemoryManager.Free(pInfo->Path);
            }
        }
    }
}