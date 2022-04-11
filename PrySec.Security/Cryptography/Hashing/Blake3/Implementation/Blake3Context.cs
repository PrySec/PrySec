using PrySec.Core.HwPrimitives;
using PrySec.Core.Memory.MemoryManagement;
using PrySec.Core.NativeTypes;
using PrySec.Security.MemoryProtection.Sentinels;
using PrySec.Security.MemoryProtection.Universal;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace PrySec.Security.Cryptography.Hashing.Blake3;
public unsafe partial class Blake3
{
    private static readonly delegate*<uint*, byte*, byte, ulong, Blake3Flags, void> _compressInPlaceImpl;
    private static readonly delegate*<byte**, Size_T, Size_T, uint*, ulong, bool, Blake3Flags, Blake3Flags, Blake3Flags, byte*, void> _hashManyImpl;

    [StructLayout(LayoutKind.Sequential)]
    private struct Blake3Context
    {
        public fixed uint Key[8];
        public Blake3ChunkState Chunk;
        public byte CvStackLength;

        // The stack size is MAX_DEPTH + 1 because we do lazy merging. For example,
        // with 7 chunks, we have 3 entries in the stack. Adding an 8th chunk
        // requires a 4th entry, rather than merging everything down to 1, because we
        // don't know whether more input is coming.
        public fixed byte CvStack[(BLAKE3_MAX_DEPTH + 1) * BLAKE3_OUT_LEN];

        private static void Initialize(Blake3Context* self, uint* key, Blake3Flags flags)
        {
            Unsafe.CopyBlockUnaligned(self->Key, key, BLAKE3_KEY_LEN);
            Blake3ChunkState.Initialize(&self->Chunk, key, flags);
            self->CvStackLength = 0;
        }

        public static void Initialize(Blake3Context* self)
        {
            fixed (uint* key = IV)
            {
                Initialize(self, key, 0);
            }
        }

        public static void InitializeKeyed(Blake3Context* self, byte* key)
        {
            uint* keyWords = stackalloc uint[BLAKE3_KEY_DWORD_LEN];
            using DeterministicSpan<uint> _ = DeterministicSpan.ProtectOnly(keyWords, BLAKE3_KEY_LEN);
            LoadKeyWords(key, keyWords);
            Initialize(self, keyWords, Blake3Flags.KEYED_HASH);
        }

        public static void Update(Blake3Context* self, byte* input, Size_T inputLength)
        {
            if (inputLength == 0)
            {
                return;
            }

            // If we have some partial chunk bytes in the internal chunk_state, we need
            // to finish that chunk first.
            Size_T chunkLength = Blake3ChunkState.GetLength(&self->Chunk);
            if (chunkLength > 0)
            {
                Size_T take = BLAKE3_CHUNK_LEN - chunkLength;
                if (take > inputLength)
                {
                    take = inputLength;
                }
                Blake3ChunkState.Update(&self->Chunk, input, take);
                input += take;
                inputLength -= take;

                // If we've filled the current chunk and there's more coming, finalize this
                // chunk and proceed. In this case we know it's not the root.
                if (inputLength > 0)
                {
                    Output_T output = default;
                    using DeterministicSentinel<Output_T> _ = DeterministicSentinel.Protect(&output);
                    byte* chunkCv = stackalloc byte[BLAKE3_OUT_LEN];
                    using DeterministicSpan<byte> _2 = DeterministicSpan.ProtectOnly(chunkCv, BLAKE3_OUT_LEN);
                    Output_T.ChainingValue(&output, chunkCv);
                    PushCv(self, chunkCv, self->Chunk.ChunkCounter);
                    Blake3ChunkState.Reset(&self->Chunk, self->Key, self->Chunk.ChunkCounter + 1);
                }
                else
                {
                    return;
                }
            }
            
            // TODO: this is still risky. We could still overflow the stack if Update() is called in a loop.
            byte* cv = stackalloc byte[BLAKE3_OUT_LEN];
            byte* cvPair = stackalloc byte[2 * BLAKE3_OUT_LEN];
            using DeterministicSpan<byte> _3 = DeterministicSpan.ProtectOnly(cv, BLAKE3_OUT_LEN);
            using DeterministicSpan<byte> _4 = DeterministicSpan.ProtectOnly(cvPair, 2 * BLAKE3_OUT_LEN);

            // Now the chunk_state is clear, and we have more input. If there's more than
            // a single chunk (so, definitely not the root chunk), hash the largest whole
            // subtree we can, with the full benefits of SIMD (and maybe in the future,
            // multi-threading) parallelism. Two restrictions:
            // - The subtree has to be a power-of-2 number of chunks. Only subtrees along
            //   the right edge can be incomplete, and we don't know where the right edge
            //   is going to be until we get to finalize().
            // - The subtree must evenly divide the total number of chunks up until this
            //   point (if total is not 0). If the current incomplete subtree is only
            //   waiting for 1 more chunk, we can't hash a subtree of 4 chunks. We have
            //   to complete the current subtree first.
            // Because we might need to break up the input to form powers of 2, or to
            // evenly divide what we already have, this part runs in a loop.
            while (inputLength > BLAKE3_CHUNK_LEN)
            {
                Size64_T subTreeLength = (Size64_T)BinaryUtils.RoundDownToPowerOf2(inputLength);
                ulong countSoFar = self->Chunk.ChunkCounter * BLAKE3_CHUNK_LEN;
                
                // Shrink the subtree_len until it evenly divides the count so far. We know
                // that subtree_len itself is a power of 2, so we can use a bitmasking
                // trick instead of an actual remainder operation. (Note that if the caller
                // consistently passes power-of-2 inputs of the same size, as is hopefully
                // typical, this loop condition will always fail, and subtree_len will
                // always be the full length of the input.)
                //
                // An aside: We don't have to shrink subtree_len quite this much. For
                // example, if count_so_far is 1, we could pass 2 chunks to
                // compress_subtree_to_parent_node. Since we'll get 2 CVs back, we'll still
                // get the right answer in the end, and we might get to use 2-way SIMD
                // parallelism. The problem with this optimization, is that it gets us
                // stuck always hashing 2 chunks. The total number of chunks will remain
                // odd, and we'll never graduate to higher degrees of parallelism. See
                // https://github.com/BLAKE3-team/BLAKE3/issues/69.
                while ((((ulong)(subTreeLength - 1)) & countSoFar) != 0)
                {
                    subTreeLength >>= 1;
                }
                // The shrunken subtree_len might now be 1 chunk long. If so, hash that one
                // chunk by itself. Otherwise, compress the subtree into a pair of CVs.
                ulong subtreeChunks = (ulong)subTreeLength / BLAKE3_CHUNK_LEN;
                if (subTreeLength <= BLAKE3_CHUNK_LEN)
                {
                    Blake3ChunkState chunkState = default;
                    Blake3ChunkState.Initialize(&chunkState, self->Key, self->Chunk.Flags);
                    chunkState.ChunkCounter = self->Chunk.ChunkCounter;
                    Blake3ChunkState.Update(&chunkState, input, (uint)(ulong)subTreeLength);
                    Output_T output = default;
                    using DeterministicSentinel<Output_T> _ = DeterministicSentinel.Protect(&output);
                    Output_T.ChainingValue(&output, cv);
                    PushCv(self, cv, chunkState.ChunkCounter);
                }
                else
                {
                    // This is the high-performance happy path, though getting here depends
                    // on the caller giving us a long enough input.
                    
                }
            }
        }

        // In reference_impl.rs, we merge the new CV with existing CVs from the stack
        // before pushing it. We can do that because we know more input is coming, so
        // we know none of the merges are root.
        //
        // This setting is different. We want to feed as much input as possible to
        // compress_subtree_wide(), without setting aside anything for the chunk_state.
        // If the user gives us 64 KiB, we want to parallelize over all 64 KiB at once
        // as a single subtree, if at all possible.
        //
        // This leads to two problems:
        // 1) This 64 KiB input might be the only call that ever gets made to update.
        //    In this case, the root node of the 64 KiB subtree would be the root node
        //    of the whole tree, and it would need to be ROOT finalized. We can't
        //    compress it until we know.
        // 2) This 64 KiB input might complete a larger tree, whose root node is
        //    similarly going to be the the root of the whole tree. For example, maybe
        //    we have 196 KiB (that is, 128 + 64) hashed so far. We can't compress the
        //    node at the root of the 256 KiB subtree until we know how to finalize it.
        //
        // The second problem is solved with "lazy merging". That is, when we're about
        // to add a CV to the stack, we don't merge it with anything first, as the
        // reference impl does. Instead we do merges using the *previous* CV that was
        // added, which is sitting on top of the stack, and we put the new CV
        // (unmerged) on top of the stack afterwards. This guarantees that we never
        // merge the root node until finalize().
        //
        // Solving the first problem requires an additional tool,
        // compress_subtree_to_parent_node(). That function always returns the top
        // *two* chaining values of the subtree it's compressing. We then do lazy
        // merging with each of them separately, so that the second CV will always
        // remain unmerged. (That also helps us support extendable output when we're
        // hashing an input all-at-once.)
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void PushCv(Blake3Context* self, byte* newCv, ulong chunkCounter)
        {
            MergeCvStack(self, chunkCounter);
            Unsafe.CopyBlockUnaligned(self->CvStack + self->CvStackLength * BLAKE3_OUT_LEN, newCv, BLAKE3_OUT_LEN);
            self->CvStackLength++;
        }

        // As described in hasher_push_cv(), we do "lazy merging", delaying
        // merges until right before the next CV is about to be added. This is
        // different from the reference implementation. Another difference is that we
        // aren't always merging 1 chunk at a time. Instead, each CV might represent
        // any power-of-two number of chunks, as long as the smaller-above-larger stack
        // order is maintained. Instead of the "count the trailing 0-bits" algorithm
        // described in the spec, we use a "count the total number of 1-bits" variant
        // that doesn't require us to retain the subtree size of the CV on top of the
        // stack. The principle is the same: each CV that should remain in the stack is
        // represented by a 1-bit in the total number of chunks (or bytes) so far.
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static void MergeCvStack(Blake3Context* self, ulong totalLength)
        {
            Size_T postMergeStackLength = BinaryUtils.PopulationCount(totalLength);
            while (self->CvStackLength > postMergeStackLength)
            {
                byte* parentNode = &self->CvStack[(self->CvStackLength - 2) * BLAKE3_OUT_LEN];
                Output_T output = default;
                using DeterministicSentinel<Output_T> _ = DeterministicSentinel.Protect(&output);
                Output_T.ChainingValue(&output, parentNode);
                self->CvStackLength -= 1;
            }
        }

        private static void CompressSubtreeToParentNode(byte* input, Size64_T inputLength, uint* key, ulong chunkCounter, Blake3Flags flags, byte* output)
        {
            // TODO: move this allocation outside of this function somewhere in the context and maybe do a lazy allocation.
            byte* cvArray = (byte*)MemoryManager.Malloc(MAX_SIMD_DEGREE_OR_2 * BLAKE3_OUT_LEN);
            Size64_T numberOfCvs = 
        }

        // The wide helper function returns (writes out) an array of chaining values
        // and returns the length of that array. The number of chaining values returned
        // is the dyanmically detected SIMD degree, at most MAX_SIMD_DEGREE. Or fewer,
        // if the input is shorter than that many chunks. The reason for maintaining a
        // wide array of chaining values going back up the tree, is to allow the
        // implementation to hash as many parents in parallel as possible.
        //
        // As a special case when the SIMD degree is 1, this function will still return
        // at least 2 outputs. This guarantees that this function doesn't perform the
        // root compression. (If it did, it would use the wrong flags, and also we
        // wouldn't be able to implement exendable output.) Note that this function is
        // not used when the whole input is only 1 chunk long; that's a different
        // codepath.
        //
        // Why not just have the caller split the input on the first update(), instead
        // of implementing this special rule? Because we don't want to limit SIMD or
        // multi-threading parallelism for that update().
        private static Size_T CompressSubtreeWide(byte* input, Size_T inputLength, uint* key, ulong chunkCounter, Blake3Flags flags, byte* output)
        {
            // Note that the single chunk case does *not* bump the SIMD degree up to 2
            // when it is 1. If this implementation adds multi-threading in the future,
            // this gives us the option of multi-threading even the 2-chunk case, which
            // can help performance on smaller platforms.
            if (inputLength <= BLAKE3_SIMD_DEGREE * BLAKE3_CHUNK_LEN)
            {
                return CompressChunksParallel(input, inputLength, key, chunkCounter, flags, output);
            }

            // With more than simd_degree chunks, we need to recurse. Start by dividing
            // the input into left and right subtrees. (Note that this is only optimal
            // as long as the SIMD degree is a power of 2. If we ever get a SIMD degree
            // of 3 or something, we'll need a more complicated strategy.)

            ///////////////////////////////////////////////////////////////////////
            //                  TODO: LEFT off here
            ///////////////////////////////////////////////////////////////////////
        }

        // Use SIMD parallelism to hash up to MAX_SIMD_DEGREE chunks at the same time
        // on a single thread. Write out the chunk chaining values and return the
        // number of chunks hashed. These chunks are never the root and never empty;
        // those cases use a different codepath.
        [MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
        private static Size_T CompressChunksParallel(byte* input, Size_T inputLength, uint* key, ulong chunkCounter, Blake3Flags flags, byte* output)
        {
            // TODO: check that we don't risk overflowing the stack. Probably need to move this allocation
            // outside of this function somewhere and try to re-use stack space where possible. Especially
            // as most methods are inlined, this might be a problem as allocations are not popped of the stack.
            byte** chunksArray = stackalloc byte*[MAX_SIMD_DEGREE];
            Size_T inputPosition = 0;
            Size_T chunksArrayLength = 0;
            while (inputLength - inputPosition >= BLAKE3_CHUNK_LEN)
            {
                chunksArray[chunksArrayLength] = input + inputPosition;
                inputPosition += BLAKE3_CHUNK_LEN;
                chunksArrayLength++;
            }

            _hashManyImpl(chunksArray,
                          chunksArrayLength,
                          BLAKE3_CHUNK_LEN / BLAKE3_BLOCK_LEN,
                          key,
                          chunkCounter,
                          true,
                          flags,
                          Blake3Flags.CHUNK_START,
                          Blake3Flags.CHUNK_END,
                          output);

            // Hash the remaining partial chunk, if there is one. Note that the empty
            // chunk (meaning the empty message) is a different codepath.
            if (inputLength > inputPosition)
            {
                ulong counter = chunkCounter + chunksArrayLength;
                Blake3ChunkState chunkState = default;
                Blake3ChunkState.Initialize(&chunkState, key, flags);
                chunkState.ChunkCounter = counter;
                Blake3ChunkState.Update(&chunkState, input + inputPosition, inputLength - inputPosition);
                Output_T chunkOutput = default;
                using DeterministicSentinel<Output_T> _ = DeterministicSentinel.Protect(&chunkOutput);
                Output_T.ChainingValue(&chunkOutput, output + chunksArrayLength * BLAKE3_OUT_LEN);
                return chunksArrayLength + 1;
            }
            else
            {
                return chunksArrayLength;
            }
        }
    }
}
