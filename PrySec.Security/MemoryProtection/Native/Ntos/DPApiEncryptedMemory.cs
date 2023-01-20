using PrySec.Core.Extensions;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using System;

namespace PrySec.Security.MemoryProtection.Native.Ntos;

public unsafe class DPApiEncryptedMemory<T> : IProtectedMemory<T>, IProtectedMemoryFactory<DPApiEncryptedMemory<T>, T>, IRequireManualAccess
    where T : unmanaged
{
    public DPApiEncryptedMemory(Size_T count)
    {
        if (count <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "count must be a positive integer.");
        }
        Count = count;
        ByteSize = count * sizeof(T);
        NativeByteSize = DPApiNativeShim.RoundToBlockSize(ByteSize);
        BasePointer = (T*)MemoryManager.Malloc(NativeByteSize);
        NativeHandle = new nint(BasePointer);
        MemoryManager.ZeroMemory(BasePointer, ByteSize);
        this.As<IRequireManualAccess>().Protect();
    }

    ~DPApiEncryptedMemory()
    {
        Dispose();
    }

    public DPApiEncryptedMemory<T> this[Range range] => throw new NotImplementedException();

    public nint NativeHandle { get; private set; }

    public unsafe T* BasePointer { get; private set; }

    public int Count { get; }

    public Size_T ByteSize { get; }

    public Size_T NativeByteSize { get; }

    ProtectionState IRequireManualAccess.State { get; set; } = ProtectionState.Unprotected;

    public static DPApiEncryptedMemory<T> Allocate(Size_T count) => new(count);
    public static DPApiEncryptedMemory<T> CreateFrom(ReadOnlySpan<T> data)
    {
        DPApiEncryptedMemory<T> memory = new(data.Length);
        using (IMemoryAccess<T> access = memory.GetAccess())
        {
            Span<T> memorySpan = access.AsSpan();
            data.CopyTo(memorySpan);
        }
        return memory;
    }
    public void Dispose()
    {
        if (NativeHandle != 0)
        {
            DPApiNativeShim.CryptUnprotectMemory(NativeHandle, NativeByteSize);
            DPApiNativeShim.SecureZeroMemory(NativeHandle, NativeByteSize);
            MemoryManager.Free(NativeHandle.ToPointer());
            NativeHandle = 0;
            BasePointer = null;
            GC.SuppressFinalize(this);
        }
    }

    public void Free() => Dispose();
    public IMemoryAccess<T> GetAccess() => new ProtectedMemoryAccess<DPApiEncryptedMemory<T>, T>(this);
    public IMemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => throw new NotImplementedException();
    public void ZeroMemory()
    {
        if (this.As<IRequireManualAccess>().State is ProtectionState.Protected)
        {
            throw new InvalidOperationException("Cannot zero memory while in protected state!");
        }
        DPApiNativeShim.SecureZeroMemory(new nint(BasePointer), ByteSize);
    }

    void IRequireManualAccess.Protect()
    {
        IRequireManualAccess self = this.As<IRequireManualAccess>();
        if (self.State is ProtectionState.Unprotected)
        {
            DPApiNativeShim.CryptProtectMemory(NativeHandle, NativeByteSize);
            self.State = ProtectionState.Protected;
        }
    }

    void IRequireManualAccess.Unprotect()
    {
        IRequireManualAccess self = this.As<IRequireManualAccess>();
        if (self.State is ProtectionState.Protected)
        {
            DPApiNativeShim.CryptUnprotectMemory(NativeHandle, NativeByteSize);
            self.State = ProtectionState.Unprotected;
        }
    }
}
