using PrySec.Core.Memory;

namespace PrySec.Security.Cryptography.Hashing.Sha;

/// <summary>
/// SHA-384 Secure Crypto Provider
/// </summary>
public unsafe class Sha384Scp : Sha2UInt64Scp
{
    private static readonly ulong[] H384 = new ulong[] {
        0xcbbb9d5dc1059ed8UL, 0x629a292a367cd507UL, 0x9159015a3070dd17UL, 0x152fecd8f70e5939UL, 0x67332667ffc00b31UL, 0x8eb44a8768581511UL, 0xdb0c2e0d64f98fa7UL, 0x47b5481dbefa4fa4UL };

    public Sha384Scp() : base(H384)
    {
    }

    private protected override int DigestOutputLength => 48;

    private protected override TOutputMemory HashCore<TOutputMemory>(ref ShaScpState state)
    {
        // create a 80-entry message schedule array w[0..79] of 64-bit words
        ulong* messageScheduleBuffer = stackalloc ulong[MESSAGE_SCHEDULE_BUFFER_LENGTH];

        TOutputMemory resultBuffer;
        using (TOutputMemory sha512ResultBuffer = HashCoreHelper<TOutputMemory>(ref state, messageScheduleBuffer))
        {
            // omit h6 and h7 in the output
            resultBuffer = sha512ResultBuffer[..DigestOutputLength];
        }
        UnsafeReference<ulong> pMessageScheduleBuffer = new(messageScheduleBuffer, MESSAGE_SCHEDULE_BUFFER_LENGTH);
        HashFinalize(ref state, ref resultBuffer, ref pMessageScheduleBuffer);
        return resultBuffer;
    }
}