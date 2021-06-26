using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PrySec.Base.Memory.MemoryManagement
{
    public class AllocationSnapshot
    {
        private readonly List<(int, string)> _allocations;

        public ulong TotalByteCount { get; }

        public AllocationSnapshot(List<(int, string)> allocations)
        {
            _allocations = allocations;
            TotalByteCount = allocations
                .Aggregate(0ul, (result, tuple) => result + (ulong)tuple.Item1);
        }

        public override string ToString()
        {
            StringBuilder builder = new(@$"
-----------------------------------------------
          Unmanaged Heap Allocations
-----------------------------------------------

{TotalByteCount} bytes currently allocated!

-----------------------------------------------

Allocations:


");
            foreach ((int bytes, string stacktrace) in _allocations)
            {
                builder.Append($@"
{bytes} bytes allocated in
{stacktrace}

");
            }
            return builder.ToString();
        }
    }
}
