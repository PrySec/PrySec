using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.CoreTests;
using PrySec.Core.Memory.MemoryManagement;
using System;

namespace PrySec.Core.Native.UnixLike.Procfs.Tests;

[TestClass]
public unsafe class ProcfsMapsParserTests : BaseTest
{
#if false
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
            //Assert.AreEqual()
            Assert.AreEqual("[stack]", pInfo->ReadPath());
            Assert.AreEqual(pInfo->Permissions, ProcfsPermissions.Read | ProcfsPermissions.Write);
            if (pInfo->Path != null)
            {
                MemoryManager.Free(pInfo->Path);
            }
        }
    }
#endif
}