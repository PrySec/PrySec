using System.Diagnostics.CodeAnalysis;
using System.Xml.Linq;

namespace PrySec.Security.MemoryProtection.Portable.ProtectedMemory;

internal unsafe interface IGuardedMemoryRegion
{
    internal nint FrontGuardHandle { get; }

    internal nint RearGuardHandle { get; }

    internal nint BaseHandle { get; }

    internal bool OnFrontGuardHandleWatchdogValidation(nint handle, void* context, [NotNullWhen(false)] out string? error);

    internal bool OnRearGuardHandleWatchdogValidation(nint handle, void* context, [NotNullWhen(false)] out string? error);

    internal bool OnBaseHandleWatchdogValidation(nint handle, void* context, [NotNullWhen(false)] out string? error);

    internal void OnWatchdogFailure();
}
