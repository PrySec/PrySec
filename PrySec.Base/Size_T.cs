using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Base
{
    public readonly struct Size_T
    {
        private readonly uint value;

        private Size_T(uint value) => this.value = value;

        public static implicit operator uint(Size_T size) => size.value;

        public static implicit operator int(Size_T size) => (int)size.value;

        public static implicit operator Size_T(int i) => new((uint)i);

        public static implicit operator Size_T(uint i) => new(i);
    }
}
