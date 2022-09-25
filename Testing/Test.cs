using BenchmarkDotNet.Attributes;
using PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;
using PrySec.Core.Memory.MemoryManagement.Implementations;
using System;
using PrySec.Core.Memory.MemoryManagement;

namespace Testing;

public class Test
{
    public static unsafe void Asdf(int i)
    {
        MemoryManager.UseImplementation<AllocationTracker<NativeMemoryManager>>();

        byte* bytes = (byte*)MemoryManager.Malloc(64);
        Guid* guids = (Guid*)MemoryManager.Calloc(32, sizeof(Guid));
        Guid* guids2 = MemoryManager.Allocator.Calloc<Guid>(32);

        AllocationSnapshot? snapshot = MemoryManager.GetAllocationSnapshot();
     
        Console.WriteLine(snapshot);
    }
}
