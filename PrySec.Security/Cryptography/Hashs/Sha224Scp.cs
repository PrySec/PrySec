using PrySec.Base.Memory;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace PrySec.Security.Cryptography.Hashs
{
    /// <summary>
    /// SHA-256 Secure Crypto Provider
    /// </summary>
    public unsafe class Sha224Scp : Sha2UInt32Scp
    {
        private static readonly uint[] H224 = new uint[] {
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4 };

        public Sha224Scp() : base(H224)
        {
        }

        private protected override DeterministicSpan<byte> HashCore(ref ShaScpState<uint> state)
        {
            // create a 64-entry message schedule array w[0..63] of 32-bit words
            uint* messageScheduleBuffer = stackalloc uint[MESSAGE_SCHEDULE_BUFFER_LENGTH];
            // omit h7 in the output
            DeterministicSpan<uint> resultBuffer = new(DIGEST_DWORD_LENGTH - 1);
            using (DeterministicSpan<uint> sha256ResultBuffer = HashCoreHelper(ref state, messageScheduleBuffer))
            {
                Unsafe.CopyBlockUnaligned(resultBuffer.BasePointer, sha256ResultBuffer.BasePointer, resultBuffer.ByteSize);
            }
            UnsafeReference<uint> pMessageScheduleBuffer = new(messageScheduleBuffer, MESSAGE_SCHEDULE_BUFFER_LENGTH);
            return HashFinalize(ref state, ref resultBuffer, ref pMessageScheduleBuffer);
        }
    }
}
