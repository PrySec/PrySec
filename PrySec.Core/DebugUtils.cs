using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Core;

public static unsafe class DebugUtils
{
    [Conditional("DEBUG")]
    public static void PrintBuffer(void* buffer, int byteCount)
    {
        for (int i = 0; i < byteCount; i++)
        {
            Console.Write(((byte*)buffer)[i].ToString("X2") + " ");
        }
        Console.WriteLine();
    }
}
