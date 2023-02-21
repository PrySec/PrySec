using System.Collections;
using System.Collections.Generic;
using PrySec.Core.Memory;

namespace PrySec.Core.Native.UnixLike.Procfs;

internal unsafe class ProcfsMemoryRegionInfoListEnumerator : IEnumerator<UnmanagedReference<ProcfsMemoryRegionInfo>>
{
    private ProcfsMemoryRegionInfoNode* _current = null;
    private readonly ProcfsMemoryRegionInfoNode* _head;
    private bool initialized = false;

    public ProcfsMemoryRegionInfoListEnumerator(ProcfsMemoryRegionInfoNode* head)
    {
        _head = head;
    }

    public UnmanagedReference<ProcfsMemoryRegionInfo> Current =>
        _current != null
            ? new UnmanagedReference<ProcfsMemoryRegionInfo>(_current->Info)
            : new UnmanagedReference<ProcfsMemoryRegionInfo>(null);

    object IEnumerator.Current => Current;

    public void Dispose()
    {
    }

    public bool MoveNext()
    {
        if (!initialized)
        {
            initialized = true;
            _current = _head;
        }
        else
        {
            _current = _current->Next;
        }
        return _current != null;
    }

    public void Reset()
    {
        _current = null;
        initialized = false;
    }
}
