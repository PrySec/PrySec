using System;
using System.Collections;
using System.Collections.Generic;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;

namespace PrySec.Core.Native.UnixLike.Procfs;

public unsafe class ProcfsMemoryRegionInfoList : IDisposable, IReadOnlyList<UnmanagedReference<ProcfsMemoryRegionInfo>>
{
    private ProcfsMemoryRegionInfoNode* _head;

    private ProcfsMemoryRegionInfoNode* _tail;

    private bool disposedValue;

    public int Count { get; private set; }

    public UnmanagedReference<ProcfsMemoryRegionInfo> this[int index]
    {
        get
        {
            if (index >= Count)
            {
                throw new IndexOutOfRangeException();
            }
            int i;
            ProcfsMemoryRegionInfoNode* node;
            if (index < Count / 2)
            {
                for (node = _head, i = 0; node != null && i < index; node = node->Next, i++) { }
                return new UnmanagedReference<ProcfsMemoryRegionInfo>(node->Info);
            }
            else
            {
                for (node = _tail, i = Count - 1; node != null && i > index; node = node->Previous, i--)  { }
                return new UnmanagedReference<ProcfsMemoryRegionInfo>(node->Info);
            }
        }
    }

    internal void Add(ProcfsMemoryRegionInfo* info)
    {
        ProcfsMemoryRegionInfoNode* node = ProcfsMemoryRegionInfoNode.Create(info);
        if (Count == 0)
        {
            _head = node;
            _tail = node;
        }
        else
        {
            node->Previous = _tail;
            _tail->Next = node;
            _tail = node;
        }
        Count++;
    }

    public IEnumerator<UnmanagedReference<ProcfsMemoryRegionInfo>> GetEnumerator() =>
        new ProcfsMemoryRegionInfoListEnumerator(_head);

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

    protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            if (disposing)
            {
                // dispose managed state (managed objects)
            }

            for (ProcfsMemoryRegionInfoNode* node = _head, tmp = null; node != null;)
            {
                tmp = node;
                node = node->Next;
                void* path;
                if ((path = tmp->Info->Path) != null)
                {
                    MemoryManager.Free(path);
                }
                MemoryManager.Free(tmp->Info);
                MemoryManager.Free(tmp);
            }
            _head = null;
            _tail = null;
            disposedValue = true;
        }
    }

    ~ProcfsMemoryRegionInfoList()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: false);
    }

    public void Dispose()
    {
        // Do not change this code. Put cleanup code in 'Dispose(bool disposing)' method
        Dispose(disposing: true);
        GC.SuppressFinalize(this);
    }
}