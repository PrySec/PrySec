namespace PrySec.Security.MemoryProtection.Native.Posix.SysMMan;

internal unsafe interface ISysMManAccessValidator
{
    bool ValidateNoAccess(nint handle, void* context);
}
