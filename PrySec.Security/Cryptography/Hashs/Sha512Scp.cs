using PrySec.Base.Memory;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashs
{
    public unsafe class Sha512Scp : Sha2UInt64Scp
    {
        private static readonly ulong[] H512 = new ulong[] {
            0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL, 0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL, 0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL, 0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL };

        public Sha512Scp() : base(H512)
        {   
        }

        private protected override DeterministicSpan<byte> HashCore(ref ShaScpState<ulong> state)
        {
            // create a 80-entry message schedule array w[0..79] of 64-bit words
            ulong* messageScheduleBuffer = stackalloc ulong[MESSAGE_SCHEDULE_BUFFER_LENGTH];
            DeterministicSpan<ulong> resultBuffer = HashCoreHelper(ref state, messageScheduleBuffer);
            UnsafeReference<ulong> pMessageScheduleBuffer = new(messageScheduleBuffer, MESSAGE_SCHEDULE_BUFFER_LENGTH);
            return HashFinalize(ref state, ref resultBuffer, ref pMessageScheduleBuffer);
        }
    }
}
