using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.Native;
using PrySec.Core.Native.UnixLike.Procfs;
using PrySec.Security.MemoryProtection.Native.Ntos.MemoryApi;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security;
using System.Threading;
using ThreadState = global::System.Threading.ThreadState;

namespace PrySec.Security.MemoryProtection.Portable.ProtectedMemory;

internal static unsafe class PageProtectionStateWatchdog
{
    private static readonly List<IMonitoredMemoryRegion> _guardedRegions = new();
    private static readonly WatchdogTaskList _watchdogTasks = new();

    internal const uint FALSE = 0;
    internal const uint TRUE = ~FALSE;

    internal static volatile uint _failed = FALSE;
    internal static volatile uint _isRunning = FALSE;

    public static void Monitor(IGuardedMemoryRegion region)
    {
        _watchdogTasks.Add(region.FrontGuardHandle, region.OnFrontGuardHandleWatchdogValidation);
        _watchdogTasks.Add(region.RearGuardHandle, region.OnRearGuardHandleWatchdogValidation);
        Monitor((IMonitoredMemoryRegion)region);
    }

    public static void Monitor(IMonitoredMemoryRegion region)
    {
        lock (_guardedRegions)
        {
            _guardedRegions.Add(region);
        }
        _watchdogTasks.Add(region.BaseHandle, region.OnBaseHandleWatchdogValidation);
        if (Interlocked.CompareExchange(ref _isRunning, TRUE, FALSE) is FALSE)
        {
            PageProtectionStateWatchdogInitializer watchdog1Initializer = new();
            PageProtectionStateWatchdogInitializer watchdog2Initializer = new();
            Thread watchdog1 = new(() => WatchdogMain(watchdog1Initializer, &Watchdog1));
            Thread watchdog2 = new(() => WatchdogMain(watchdog2Initializer, &Watchdog2));
            watchdog1Initializer.Other = watchdog2;
            watchdog2Initializer.Other = watchdog1;
            watchdog1.Start();
            watchdog2.Start();
        }
    }

    public static void Disregard(IGuardedMemoryRegion region)
    {
        if (_failed == TRUE)
        {
            return;
        }
        _watchdogTasks.Remove(region.FrontGuardHandle);
        _watchdogTasks.Remove(region.RearGuardHandle);
        Disregard((IMonitoredMemoryRegion)region);
    }

    public static void Disregard(IMonitoredMemoryRegion region)
    {
        if (_failed == TRUE)
        {
            return;
        }
        _watchdogTasks.Remove(region.BaseHandle);
        lock (_guardedRegions)
        {
            _guardedRegions.Remove(region);
        }
    }

    private static void WatchdogMain(PageProtectionStateWatchdogInitializer initializer, delegate*<PageProtectionStateWatchdogInitializer, void**, void> watchdog)
    {
        void* context = null;
        try
        {
            watchdog(initializer, &context);
        }
        finally
        {
            WatchdogRaiseViolation(WatchdogExitStatus.UNEXPECTED_TERMINATION, nameof(WatchdogExitStatus.UNEXPECTED_TERMINATION));
            if (context != null)
            {
                MemoryManager.Free(context);
            }
            Debug.WriteLine("Watchdog exited!");
        }
    }

    private static void Watchdog1(PageProtectionStateWatchdogInitializer initializer, void** pContext)
    {
        Debug.WriteLine("Watchdog1 is starting ...");
        *pContext = AllocateContextStructure();
        void* context = *pContext;
        Thread.Sleep(100);
        if (initializer.Other is null)
        {
            WatchdogRaiseViolation(WatchdogExitStatus.FAILED_TO_INITIALIZE, nameof(WatchdogExitStatus.FAILED_TO_INITIALIZE));
            return;
        }
        Debug.WriteLine("Watchdog1 is running!");
        Thread other = initializer.Other;
        while (true)
        {
            for (WatchdogTaskNode? node = _watchdogTasks.Root; node is not null; node = node.Next)
            {
                if (!node.Task.Monitor(node.Task.Handle, context, out string? error))
                {
                    WatchdogRaiseViolation(WatchdogExitStatus.ACCESS_VIOLATION, error);
                    return;
                }
            }
            if (other.ThreadState is not (ThreadState.Running or ThreadState.WaitSleepJoin or ThreadState.Unstarted))
            {
                WatchdogRaiseViolation(WatchdogExitStatus.MONITORED_WATCHDOG_EXITED, nameof(WatchdogExitStatus.MONITORED_WATCHDOG_EXITED));
                return;
            }
            Thread.Sleep(5);
        }
    }

    private static void Watchdog2(PageProtectionStateWatchdogInitializer initializer, void** pContext)
    {
        Debug.WriteLine("Watchdog2 is starting ...");
        *pContext = AllocateContextStructure();
        void* context = *pContext;
        Thread.Sleep(100);
        if (initializer.Other is null)
        {
            WatchdogRaiseViolation(WatchdogExitStatus.FAILED_TO_INITIALIZE, nameof(WatchdogExitStatus.FAILED_TO_INITIALIZE));
            return;
        }
        Debug.WriteLine("Watchdog2 is running!");
        Thread other = initializer.Other;
        while (true)
        {
            for (WatchdogTaskNode? node = _watchdogTasks.Tail; node is not null; node = node.Prev)
            {
                if (!node.Task.Monitor(node.Task.Handle, context, out string? error))
                {
                    WatchdogRaiseViolation(WatchdogExitStatus.ACCESS_VIOLATION, error);
                    return;
                }
            }
            if (other.ThreadState is not (ThreadState.Running or ThreadState.WaitSleepJoin or ThreadState.Unstarted))
            {
                WatchdogRaiseViolation(WatchdogExitStatus.MONITORED_WATCHDOG_EXITED, nameof(WatchdogExitStatus.MONITORED_WATCHDOG_EXITED));
                return;
            }
            Thread.Sleep(5);
        }
    }

    private static void* AllocateContextStructure() => 
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
        ? MemoryManager.Malloc(Marshal.SizeOf<MEMORY_BASIC_INFORMATION>())
        : OS.IsPlatform(OSPlatform.OSX)
            ? null
            : MemoryManager.Malloc(sizeof(ProcfsMemoryRegionInfo)); 

    private static void WatchdogRaiseViolation(WatchdogExitStatus exitStatus, string error)
    {
        if (Interlocked.CompareExchange(ref _failed, TRUE, FALSE) == TRUE)
        {
            return;
        }
        string message = $"Watchdog violation raised: '{exitStatus}: {error}'";
        Debug.WriteLine(message);
        lock (_guardedRegions)
        {
            foreach (IMonitoredMemoryRegion region in _guardedRegions)
            {
                region.OnWatchdogFailure();
            }
            _guardedRegions.Clear();
        }
        throw new SecurityException(message);
    }

    private enum WatchdogExitStatus
    {
        ACCESS_VIOLATION,
        UNEXPECTED_TERMINATION,
        MONITORED_WATCHDOG_EXITED,
        FAILED_TO_INITIALIZE
    }
}

internal unsafe delegate bool WatchdogTaskAction(nint handle, void* context, [NotNullWhen(false)] out string? error);

internal readonly struct WatchdogTask
{
    public readonly nint Handle;
    public readonly WatchdogTaskAction Monitor;

    public WatchdogTask(nint handle, WatchdogTaskAction taskAction)
    {
        Handle = handle;
        Monitor = taskAction;
    }
}

internal class WatchdogTaskNode
{
    public WatchdogTask Task { get; }

    public WatchdogTaskNode? Next;

    public WatchdogTaskNode? Prev;

    public WatchdogTaskNode(WatchdogTask task)
    {
        Task = task;
    }
}

internal class WatchdogTaskList
{
    public WatchdogTaskNode? Root;
    public WatchdogTaskNode? Tail;

    public void Add(nint handle, WatchdogTaskAction action)
    {
        lock (this)
        {
            WatchdogTaskNode newNode = new(new WatchdogTask(handle, action));
            if (Root is null || Tail is null)
            {
                Root = newNode;
                Tail = newNode;
                return;
            }
            newNode.Prev = Tail;
            Tail.Next = newNode;
            Interlocked.Exchange(ref Tail, newNode);
        }
    }

    public void Remove(nint handle)
    {
        lock (this)
        {
            for (WatchdogTaskNode? node = Root; node is not null; node = node.Next)
            {
                if (node.Task.Handle == handle)
                {
                    // unlink node
                    if (node.Prev is not null)
                    {
                        Interlocked.Exchange(ref node.Prev.Next, node.Next);
                    }
                    if (node.Next is not null)
                    {
                        Interlocked.Exchange(ref node.Next.Next, node.Prev);
                    }
                    return;
                }
            }
        }
    }
}

internal class PageProtectionStateWatchdogInitializer
{
    public Thread? Other { get; set; }
}