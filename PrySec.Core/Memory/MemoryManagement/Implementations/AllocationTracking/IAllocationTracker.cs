namespace PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;

public interface IAllocationTracker
{
    AllocationSnapshot GetAllocationSnapshot(bool reset);
}