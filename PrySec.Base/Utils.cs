using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Core
{
    public static unsafe class Utils
    {
        public static void PrintBuffer(byte* buffer, int count)
        {
            for (int i = 0; i < count; i++)
            {
                Console.Write(buffer[i].ToString("X2") + " ");
            }
        }
    }
}
