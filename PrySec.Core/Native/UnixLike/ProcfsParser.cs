using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;

namespace PrySec.Core.Native.UnixLike;

public unsafe class ProcfsMapsParser
{
    public ProcfsMemoryRegionInfoList QueryProcfsEx(int pid)
    {
        ProcfsMemoryRegionInfoList procfsInfo = new();
        using Stream stream = File.OpenRead($"/proc/{pid}/maps");
        return default;
    }
}

public unsafe class ProcfsMemoryRegionInfoList : IDisposable, IReadOnlyList<UnmanagedReference<ProcfsMemoryRegionInfo>>
{
    private ProcfsMemoryRegionInfoNode* _head;

    private ProcfsMemoryRegionInfoNode* _tail;

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
                for (node = _head, i = 0; node != null && i < index; node = node->Next, i++);
                return new UnmanagedReference<ProcfsMemoryRegionInfo>(node->Info);
            }
            else
            {
                for (node = _tail, i = Count - 1; node != null && i > index; node = node->Previous, i--);
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
            Count++;
        }
    }

    public void Dispose()
    {
        for (ProcfsMemoryRegionInfoNode* node = _head, tmp = null; node != null; )
        {
            tmp = node;
            node = node->Next;
            MemoryManager.Free(tmp->Info);
            MemoryManager.Free(tmp);
        }
        _head = null;
        _tail = null;
    }

    public IEnumerator<UnmanagedReference<ProcfsMemoryRegionInfo>> GetEnumerator()
    {
        return new ProcfsMemoryRegionInfoListEnumerator(_head);
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}

internal unsafe class ProcfsMemoryRegionInfoListEnumerator : IEnumerator<UnmanagedReference<ProcfsMemoryRegionInfo>>
{
    private ProcfsMemoryRegionInfoNode* _current = null;
    private readonly ProcfsMemoryRegionInfoNode* _head;
    private bool initialized = false;

    public ProcfsMemoryRegionInfoListEnumerator(ProcfsMemoryRegionInfoNode* head)
    {
        _head = head;
    }

    public UnmanagedReference<ProcfsMemoryRegionInfo> Current
    {
        get
        {
            if (_current != null)
            {
                return new UnmanagedReference<ProcfsMemoryRegionInfo>(_current->Info);
            }
            return new UnmanagedReference<ProcfsMemoryRegionInfo>(null);
        }
    }

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

internal unsafe struct ProcfsMemoryRegionInfoNode
{
    public ProcfsMemoryRegionInfo* Info;
    public ProcfsMemoryRegionInfoNode* Previous;
    public ProcfsMemoryRegionInfoNode* Next;

    public static ProcfsMemoryRegionInfoNode* Create(ProcfsMemoryRegionInfo* info)
    {
        ProcfsMemoryRegionInfoNode* node = (ProcfsMemoryRegionInfoNode*)MemoryManager.Malloc(sizeof(ProcfsMemoryRegionInfoNode));
        node->Info = info;
        return node;
    }
}

public unsafe readonly struct ProcfsMemoryRegionInfo
{
    public readonly nint RegionStartAddress;
    public readonly nint RegionEndAddress;
    public readonly Size_T RegionSize;
    public readonly ProcfsPermissions Permissions;
    public readonly nuint Offset;
    public readonly ProcfsDevice Device;
    public readonly nint Inode;
    public readonly byte* Path;
    public readonly int PathLength;

    public readonly string? ReadPath()
    {
        if (Path != null)
        {
            return Encoding.ASCII.GetString(Path, PathLength);
        }
        return null;
    }
}

[Flags]
public enum ProcfsPermissions : int
{
    NoAccess = 0x0,
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
    Shared = 0x8,
}

public readonly struct ProcfsDevice
{
    public readonly byte Major;
    public readonly byte Minor;

    public ProcfsDevice(byte major, byte minor)
    {
        Major = major;
        Minor = minor;
    }
}