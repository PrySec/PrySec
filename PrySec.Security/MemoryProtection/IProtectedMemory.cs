using PrySec.Base.Memory;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.MemoryProtection
{
    public interface IProtectedMemory<T> : IUnmanaged<T> where T : unmanaged
    {
        IntPtr NativeHandle { get; }

        void ZeroMemory();
    }
}
