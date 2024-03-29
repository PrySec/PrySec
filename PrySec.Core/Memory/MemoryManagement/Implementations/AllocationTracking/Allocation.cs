﻿using System;
using System.Diagnostics;

namespace PrySec.Core.Memory.MemoryManagement.Implementations.AllocationTracking;

public readonly record struct Allocation(IntPtr Pointer, ulong Size, StackTrace Trace)
{
    private StackFrame CallSite { get; } = Trace.GetFrame(0)!;

    // Asdf at offset 293 in file:line:column <filename unknown>:0:0
    public override string ToString() => $"0x{Pointer:x}: {Size} bytes requested by {CallSite.GetMethod()?.DeclaringType?.FullName}::{CallSite.GetMethod()} at IL offset {CallSite.GetILOffset()}. Stack trace:\n{Trace}";
}