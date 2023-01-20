namespace PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;

public interface IAllocationTracker
{
    void Clear();

    AllocationSnapshot GetAllocationSnapshot(bool reset);
}