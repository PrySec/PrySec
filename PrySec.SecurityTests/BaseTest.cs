using Microsoft.VisualStudio.TestTools.UnitTesting;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;

namespace PrySec.SecurityTests;

public abstract class BaseTest
{
    static BaseTest()
    {
        MemoryManager.UseImplementation<ThreadLocalAllocationTracker<NativeMemoryManager>>();
    }

    [ClassInitialize]
    public virtual void OnClassInitialize()
    {
        AssertMemoryFreed();
    }

    [TestInitialize]
    public virtual void OnTestInitialize()
    {
    }

    [TestCleanup]
    public virtual void OnTestCleanup()
    {
        AssertMemoryFreed();
    }

    protected void AssertMemoryFreed()
    {
        AllocationSnapshot snapshot = MemoryManager.GetAllocationSnapshot(true);
        Assert.AreEqual(0ul, snapshot.TotalByteCount, snapshot.ToString());
    }
}
