using PrySec.Core.NativeTypes;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Core;

[DebuggerStepThrough]
public static unsafe class DebugUtils
{
    [Conditional("DEBUG")]
    public static void PrintBuffer(void* buffer, Size_T byteCount)
    {
        for (int i = 0; i < byteCount; i++)
        {
            Console.Write(((byte*)buffer)[i].ToString("X2") + " ");
        }
        Console.WriteLine();
    }

    [Conditional("DEBUG")]
    public static void PrintBufferDebug(void* buffer, Size_T byteCount)
    {
        for (int i = 0; i < byteCount; i++)
        {
            Debug.Write(((byte*)buffer)[i].ToString("X2") + " ");
        }
        Debug.WriteLine(string.Empty);
    }
}
