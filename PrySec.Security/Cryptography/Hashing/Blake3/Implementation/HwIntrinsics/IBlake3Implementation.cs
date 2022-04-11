using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashing.Blake3;

public unsafe partial class Blake3
{
    private interface IBlake3Implementation
    {
        static abstract void Blake3ContextInit(Blake3Context* s);
    }
}
