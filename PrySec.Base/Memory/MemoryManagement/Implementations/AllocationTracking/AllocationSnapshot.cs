using System;
using System.Linq;
using System.Text;

namespace PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;

public record AllocationSnapshot
{
    public Allocation[] Allocations { get; }

    public ulong TotalByteCount { get; }

    public AllocationSnapshot(Allocation[] allocations)
    {
        Allocations = allocations;
        TotalByteCount = allocations.Aggregate(0ul, (sum, allocation) => sum + allocation.Size, sum => sum);
    }

    public override string ToString()
    {
        StringBuilder builder = new($"{TotalByteCount} bytes currently allocated.{Environment.NewLine}Allocations:{Environment.NewLine}");
        for (int i = 0; i < Allocations.Length; i++)
        {
            ref Allocation allocation = ref Allocations[i];
            builder
                .Append("  ")
                .Append(allocation.ToString())
                .Append(Environment.NewLine);
        }
        return builder.ToString();
    }
}