using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.SecurityTests;

public abstract class BaseTest
{
    static BaseTest()
    {
        MemoryManager.UseImplementation<ThreadLocalAllocationTracker<NativeMemoryManager>>();
    }

    protected void AssertMemoryFreed()
    {
        AllocationSnapshot snapshot = MemoryManager.GetAllocationSnapshot(true);
        Assert.AreEqual(0ul, snapshot.TotalByteCount, snapshot.ToString());
    }
}
