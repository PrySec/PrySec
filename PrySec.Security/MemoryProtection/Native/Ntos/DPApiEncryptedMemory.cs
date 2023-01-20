using PrySec.Core.Extensions;
using PrySec.Core.Interop.Ntos;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Security.MemoryProtection.Native.Ntos;

public unsafe class DPApiEncryptedMemory<T> : IProtectedMemoryFactory<DPApiEncryptedMemory<T>, T>, IProtectedMemoryProxy
    where T : unmanaged
{
    private protected DPApiEncryptedMemory(Size_T count)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "count must be a non-negative integer.");
        }
        if (count != 0)
        {
            Count = count;
            ByteSize = count * sizeof(T);
            NativeByteSize = DPApiNativeShim.RoundToNextBlockSize(ByteSize);
            BasePointer = (T*)MemoryManager.Malloc(NativeByteSize);
            NativeHandle = new nint(BasePointer);
            MemoryManager.ZeroMemory(BasePointer, ByteSize);
            this.As<IProtectedResource>().Protect();
        }
    }

    ~DPApiEncryptedMemory()
    {
        Dispose(false);
    }

    public DPApiEncryptedMemory<T> this[Range range]
    {
        get
        {
            int count = range.End.Value - range.Start.Value;
            if (count <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(range));
            }
            DPApiEncryptedMemory<T> result = new(count);
            using (IMemoryAccess<T> source = GetAccess())
            using (IMemoryAccess<T> target = result.GetAccess())
            {
                MemoryManager.Memcpy(target.Pointer, source.Pointer + range.Start.Value, count * sizeof(T));
            }
            return result;
        }
    }

    public nint NativeHandle { get; private set; }

    public unsafe T* BasePointer { get; private set; }

    public int Count { get; }

    public Size_T ByteSize { get; }

    public Size_T NativeByteSize { get; }

    internal ProtectionState State { get; set; } = ProtectionState.Unprotected;

    ProtectionState IProtectedResource.State => State;

    void* IProtectedMemoryProxy.BasePointerInternal => BasePointer;

    public static DPApiEncryptedMemory<T> Allocate(Size_T count) => count == 0 
        ? new DPApiEncryptedMemoryZeroAlloc<T>() 
        : (DPApiEncryptedMemory<T>)(new(count));

    public static DPApiEncryptedMemory<T> CreateFrom(ReadOnlySpan<T> data)
    {
        DPApiEncryptedMemory<T> memory = Allocate(data.Length);
        using (IMemoryAccess<T> access = memory.GetAccess())
        {
            data.CopyTo(access.AsSpan());
        }
        return memory;
    }

    public void Dispose() => Dispose(true);

    private protected virtual void Dispose(bool disposing)
    {
        if (NativeHandle != 0)
        {
            if (disposing)
            {
                GC.SuppressFinalize(this);
            }
            DPApiNativeShim.CryptUnprotectMemory(NativeHandle, NativeByteSize);
            MemoryManager.ZeroMemory(NativeHandle, NativeByteSize);
            MemoryManager.Free(NativeHandle);
            NativeHandle = 0;
            BasePointer = null;
        }
        else
        {
            throw new ObjectDisposedException(GetType().Name);
        }
    }

    public void Free() => Dispose();

    public IMemoryAccess<T> GetAccess() => new ProtectedMemoryAccess<DPApiEncryptedMemory<T>, T>(this);

    public IMemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => 
        new ProtectedMemoryAccess<DPApiEncryptedMemory<T>, TAs>(this);

    private protected virtual void Protect()
    {
        if (NativeHandle is not 0 && State is ProtectionState.Unprotected)
        {
            DPApiNativeShim.CryptProtectMemory(NativeHandle, NativeByteSize);
            State = ProtectionState.Protected;
        }
    }

    private protected virtual void Unprotect()
    {
        if (NativeHandle is not 0 && State is ProtectionState.Protected)
        {
            DPApiNativeShim.CryptUnprotectMemory(NativeHandle, NativeByteSize);
            State = ProtectionState.Unprotected;
        }
    }

    private protected virtual void ZeroMemory()
    {
        if (NativeHandle is not 0 && State is ProtectionState.Unprotected)
        {
            MemoryManager.ZeroMemory(BasePointer, ByteSize);
        }
        else
        {
            throw new InvalidOperationException("Cannot zero memory while in protected state!");
        }
    }

    void IProtectedResource.Protect() => Protect();

    void IProtectedResource.Unprotect() => Unprotect();

    void IProtectedMemoryProxy.ZeroMemory() => ZeroMemory();
}

file sealed class DPApiEncryptedMemoryZeroAlloc<T> : DPApiEncryptedMemory<T> where T : unmanaged
{
    public DPApiEncryptedMemoryZeroAlloc() : base(0)
    {
    }

    private protected override void Dispose(bool disposing) { }
}