namespace PrySec.Core.Memory;

/// <summary>
/// Allows pointer types as type parameters.
/// </summary>
/// <typeparam name="T"></typeparam>
public unsafe readonly struct UnmanagedReference<T> where T : unmanaged
{
    public readonly T* Pointer;

    public UnmanagedReference(T* ptr)
    {
        Pointer = ptr;
    }
}