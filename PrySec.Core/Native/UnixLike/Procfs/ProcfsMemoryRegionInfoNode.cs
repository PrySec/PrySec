using PrySec.Core.Memory.MemoryManagement;

namespace PrySec.Core.Native.UnixLike.Procfs;

internal unsafe struct ProcfsMemoryRegionInfoNode
{
    public ProcfsMemoryRegionInfo* Info;
    public ProcfsMemoryRegionInfoNode* Previous;
    public ProcfsMemoryRegionInfoNode* Next;

    public static ProcfsMemoryRegionInfoNode* Create(ProcfsMemoryRegionInfo* info)
    {
        ProcfsMemoryRegionInfoNode* node = (ProcfsMemoryRegionInfoNode*)MemoryManager.Calloc(1, sizeof(ProcfsMemoryRegionInfoNode));
        node->Info = info;
        return node;
    }
}