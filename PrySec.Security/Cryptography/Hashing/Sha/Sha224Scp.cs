using PrySec.Core.Memory;

namespace PrySec.Security.Cryptography.Hashing.Sha;

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

    private protected override int DigestOutputLength => 28;

    private protected override TOutputMemory HashCore<TOutputMemory>(ref ShaScpState state)
    {
        // create a 64-entry message schedule array w[0..63] of 32-bit words
        uint* messageScheduleBuffer = stackalloc uint[MESSAGE_SCHEDULE_BUFFER_LENGTH];
        // omit h7 in the output
        TOutputMemory resultBuffer;
        using (TOutputMemory sha256ResultBuffer = HashCoreHelper<TOutputMemory>(ref state, messageScheduleBuffer))
        {
            resultBuffer = sha256ResultBuffer[..DigestOutputLength];
        }
        UnsafeReference<uint> pMessageScheduleBuffer = new(messageScheduleBuffer, MESSAGE_SCHEDULE_BUFFER_LENGTH);
        HashFinalize(ref state, ref resultBuffer, ref pMessageScheduleBuffer);
        return resultBuffer;
    }
}