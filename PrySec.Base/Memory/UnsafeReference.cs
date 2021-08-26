using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Base.Memory
{
    public unsafe readonly struct UnsafeReference<T> where T : unmanaged
    {
        public readonly T* Pointer;

        public readonly int Size;

        public readonly Size_T ByteSize;

        public UnsafeReference(T* ptr, int size)
        {
            Pointer = ptr;
            Size = size;
            ByteSize = size * sizeof(T);
        }
    }
}
