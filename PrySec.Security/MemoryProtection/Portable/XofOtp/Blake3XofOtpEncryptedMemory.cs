using PrySec.Core.Extensions;
using PrySec.Core.Memory;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.Cryptography.Crng;
using System;

namespace PrySec.Security.MemoryProtection.Portable.XofOtp;

public unsafe class Blake3XofOtpEncryptedMemory<T> : IProtectedMemoryFactory<Blake3XofOtpEncryptedMemory<T>, T>, IProtectedMemoryProxy
    where T : unmanaged
{
    private bool disposedValue = false;

    public static int IVSize => 64;

    private protected Blake3XofOtpEncryptedMemory(Size_T count)
    {
        if (count < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(count), "count must be a non-negative integer.");
        }
        if (count != 0)
        {
            Count = count;
            ByteSize = count * sizeof(T);
            NativeByteSize = IVSize + ByteSize;
            void* nativeBase = MemoryManager.Malloc(NativeByteSize);
            NativeHandle = new nint(nativeBase);
            BasePointer = (byte*)nativeBase + IVSize;
            SecureRandom.Fill(nativeBase, IVSize);
            MemoryManager.ZeroMemory(BasePointer, ByteSize);
            this.As<IProtectedResource>().Protect();
        }
    }

    public Blake3XofOtpEncryptedMemory<T> this[Range range]
    {
        get
        {
            int count = range.End.Value - range.Start.Value;
            if (count <= 0)
            {
                throw new ArgumentOutOfRangeException(nameof(range));
            }
            Blake3XofOtpEncryptedMemory<T> result = Allocate(count);
            using (IMemoryAccess<T> source = GetAccess())
            using (IMemoryAccess<T> target = result.GetAccess())
            {
                MemoryManager.Memcpy(target.Pointer, source.Pointer + range.Start.Value, count * sizeof(T));
            }
            return result;
        }
    }

    public nint NativeHandle { get; private set; }

    public Size_T NativeByteSize { get; }

    public T* DataPointer => (T*)BasePointer;

    public int Count { get; }

    public Size_T ByteSize { get; }

    public void* BasePointer { get; private set; }

    internal ProtectionState State { get; set; } = ProtectionState.Unprotected;

    ProtectionState IProtectedResource.State => State;

    public static Blake3XofOtpEncryptedMemory<T> Allocate(Size_T count) => new(count);

    public static Blake3XofOtpEncryptedMemory<T> CreateFrom(ReadOnlySpan<T> data)
    {
        Blake3XofOtpEncryptedMemory<T> memory = Allocate(data.Length);
        using (IMemoryAccess<T> access = memory.GetAccess())
        {
            data.CopyTo(access.AsSpan());
        }
        return memory;
    }

    public void Free() => Dispose();

    public IMemoryAccess<T> GetAccess() => 
        new ProtectedMemoryAccess<Blake3XofOtpEncryptedMemory<T>, T>(this);

    public IMemoryAccess<TAs> GetAccess<TAs>() where TAs : unmanaged => 
        new ProtectedMemoryAccess<Blake3XofOtpEncryptedMemory<T>, TAs>(this);

    private protected virtual void Dispose(bool disposing)
    {
        if (!disposedValue)
        {
            //if (disposing)
            //{
            //    // TODO: dispose managed state (managed objects)
            //}

            // don't need to unprotect. Just free!
            MemoryManager.ZeroMemory(NativeHandle, NativeByteSize);
            MemoryManager.Free(NativeHandle);
            NativeHandle = 0;
            BasePointer = null;

            disposedValue = true;
        }
    }

    ~Blake3XofOtpEncryptedMemory()
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

    private protected virtual void ZeroMemory()
    {
        if (disposedValue)
        {
            throw new ObjectDisposedException(GetType().Name);
        }
        if (State is ProtectionState.Unprotected)
        {
            MemoryManager.ZeroMemory(BasePointer, ByteSize);
        }
        else
        {
            throw new InvalidOperationException("Cannot zero memory while in protected state!");
        }
    }

    void IProtectedMemoryProxy.ZeroMemory() => ZeroMemory();

    void IProtectedResource.Protect() => Blake3XofOtpEncryptionService.Protect(this);

    void IProtectedResource.Unprotect() => Blake3XofOtpEncryptionService.Unprotect(this);
}

file sealed class Blake3XofOtpEncryptedMemoryZeroAlloc<T> : Blake3XofOtpEncryptedMemory<T> where T : unmanaged
{
    public Blake3XofOtpEncryptedMemoryZeroAlloc() : base(0)
    {
    }

    private protected override void Dispose(bool disposing) { }
}