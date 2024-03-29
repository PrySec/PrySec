﻿using PrySec.Core.Memory;

namespace PrySec.Security.Cryptography.Hashing.Sha;

/// <summary>
/// SHA-256 Secure Crypto Provider
/// </summary>
public unsafe class Sha256Scp : Sha2UInt32Scp
{
    private static readonly uint[] H256 = new uint[] 
    {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 
    };

    public Sha256Scp() : base(H256)
    {
    }

    private protected override int DigestOutputLength => 32;

    private protected override TOutputMemory HashCore<TOutputMemory>(ref ShaScpState state)
    {
        // create a 64-entry message schedule array w[0..63] of 32-bit words
        uint* messageScheduleBuffer = stackalloc uint[MESSAGE_SCHEDULE_BUFFER_LENGTH];
        TOutputMemory resultBuffer = HashCoreHelper<TOutputMemory>(ref state, messageScheduleBuffer);
        UnsafeReference<uint> pMessageScheduleBuffer = new(messageScheduleBuffer, MESSAGE_SCHEDULE_BUFFER_LENGTH);
        HashFinalize(ref state, ref resultBuffer, ref pMessageScheduleBuffer);
        return resultBuffer;
    }
}