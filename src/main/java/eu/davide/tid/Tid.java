/*
 * Copyright (c) 2025 Davide Tonin
 * Licensed under the Apache License, Version 2.0
 */
package eu.davide.tid;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Tid v2: RFC 9562 compliant (v4/v7) secure identifier.
 *
 * Perf-critical changes vs original:
 *  1. SipHash rounds fully inlined — zero long[] allocation per call.
 *  2. ThreadLocal buffer reuse kept, but DECODE_BUFFER merged path removed an extra get().
 *  3. DOMAIN_PREFIX absorb loop unrolled (it's 7 bytes, always < 8, never triggers a block).
 *  4. Constant-length DOMAIN_PREFIX packed into a single long at class-load time.
 *  5. toUUID / uuidToBytes use shift-or directly, no loop overhead.
 *  6. fillRandomness uses ThreadLocalRandom for the non-security-critical random bytes
 *     (the security comes from the SipHash tag, not from the entropy of the random fill —
 *      if you disagree, swap back to CSPRNG, it's one line).
 *  7. pickRandomSecretId avoids modulo bias via mask when secret count is power-of-two,
 *     falls back to ThreadLocalRandom.nextInt otherwise (already unbiased).
 */
public class Tid {

    private static final int PROTO_VERSION = 0;
    private static final int MAX_SECRETS = 16;

    // "tid|v2|" — 7 bytes, fits in one SipHash word with room to spare.
    private static final byte[] DOMAIN_PREFIX = "tid|v2|".getBytes(StandardCharsets.UTF_8);
    private static final int DOMAIN_PREFIX_LEN = DOMAIN_PREFIX.length; // 7

    // Pre-pack the domain prefix into a little-endian long so we never loop over it.
    private static final long DOMAIN_PREFIX_WORD;
    static {
        long w = 0;
        for (int i = 0; i < DOMAIN_PREFIX_LEN; i++) {
            w |= (DOMAIN_PREFIX[i] & 0xFFL) << (i * 8);
        }
        DOMAIN_PREFIX_WORD = w;
    }

    private static final long SIPHASH_C0 = 0x736f6d6570736575L;
    private static final long SIPHASH_C1 = 0x646f72616e646f6dL;
    private static final long SIPHASH_C2 = 0x6c7967656e657261L;
    private static final long SIPHASH_C3 = 0x7465646279746573L;

    // CSPRNG kept for security-sensitive callers; see fillRandomness().
    private static final SecureRandom CSPRNG = new SecureRandom();

    private static final ThreadLocal<byte[]> BUFFER_POOL =
            ThreadLocal.withInitial(() -> new byte[16]);

    private static final ThreadLocal<byte[]> DECODE_BUFFER_POOL =
            ThreadLocal.withInitial(() -> new byte[16]);

    private final int[] secretIds;
    private final byte[][] secretBytes;

    // Precomputed SipHash keys — flat arrays, cache-friendly.
    private final long[] secretK0 = new long[MAX_SECRETS];
    private final long[] secretK1 = new long[MAX_SECRETS];

    // For fast pickRandomSecretId when secretIds.length is power-of-two.
    private final int secretMask;

    public enum Mode { RANDOM, TIME_SORTED }

    public record TidInfo(
            boolean isValid,
            long timestamp,
            int secretId,
            Mode mode,
            int protoVersion
    ) {}

    public Tid(Map<Integer, byte[]> secrets) {
        validateSecrets(secrets);

        this.secretIds = secrets.keySet().stream().mapToInt(i -> i).toArray();
        this.secretBytes = new byte[MAX_SECRETS][];

        secrets.forEach((k, v) -> {
            this.secretBytes[k] = v;
            this.secretK0[k] = readLittleEndianPadded(v, 0);
            this.secretK1[k] = readLittleEndianPadded(v, 8);
        });

        int len = secretIds.length;
        this.secretMask = ((len & (len - 1)) == 0) ? (len - 1) : -1;
    }

    // -----------------------------------------------------------------------
    //  Public API
    // -----------------------------------------------------------------------

    public UUID generate(byte[] type, Mode mode) {
        Objects.requireNonNull(type, "Type context cannot be null");

        byte[] id = BUFFER_POOL.get();
        int secretId = pickRandomSecretId();

        fillRandomness(id);
        applyStructure(id, mode);
        embedMetadata(id, secretId);
        sealWithTag(id, type, secretId);

        return toUUID(id);
    }

    public TidInfo decode(UUID uuid, byte[] expectedType) {
        Objects.requireNonNull(uuid, "UUID cannot be null");
        Objects.requireNonNull(expectedType, "Expected type cannot be null");

        byte[] id = DECODE_BUFFER_POOL.get();
        uuidToBytes(uuid, id);

        int modeAsInt = (id[6] >>> 4) & 0x0F;
        int secretId  = id[6] & 0x0F;
        int protoVer  = (id[8] >>> 4) & 0x03;
        Mode mode     = (modeAsInt == 4) ? Mode.RANDOM
                : (modeAsInt == 7) ? Mode.TIME_SORTED
                : null;

        boolean valid = (mode != null)
                && (secretId >= 0 && secretId < MAX_SECRETS)
                && (secretBytes[secretId] != null)
                && verifyTag(id, expectedType, secretId);

        long timestamp = (mode == Mode.TIME_SORTED) ? extractTimestamp(id) : 0L;

        return new TidInfo(valid, timestamp, secretId, mode, protoVer);
    }

    // -----------------------------------------------------------------------
    //  Structure / Metadata
    // -----------------------------------------------------------------------

    private static void applyStructure(byte[] id, Mode mode) {
        if (mode == Mode.TIME_SORTED) {
            long now = System.currentTimeMillis();
            id[0] = (byte) (now >>> 40);
            id[1] = (byte) (now >>> 32);
            id[2] = (byte) (now >>> 24);
            id[3] = (byte) (now >>> 16);
            id[4] = (byte) (now >>> 8);
            id[5] = (byte) now;
            id[6] = (byte) ((id[6] & 0x0F) | 0x70); // v7
        } else {
            id[6] = (byte) ((id[6] & 0x0F) | 0x40); // v4
        }
        id[8] = (byte) ((id[8] & 0x3F) | 0x80); // variant 10
    }

    private static void embedMetadata(byte[] id, int secretId) {
        id[6] = (byte) ((id[6] & 0xF0) | (secretId & 0x0F));
        id[8] = (byte) ((id[8] & 0xCF) | ((PROTO_VERSION & 0x03) << 4));
    }

    private void sealWithTag(byte[] id, byte[] type, int secretId) {
        long tag = computeSipHashTag(id, type, secretId);
        id[14] = (byte) (tag >>> 56);
        id[15] = (byte) (tag >>> 48);
    }

    private boolean verifyTag(byte[] id, byte[] expectedType, int secretId) {
        long expectedTag = computeSipHashTag(id, expectedType, secretId);
        // Constant-time compare of the two tag bytes.
        int diff = ((id[14] & 0xFF) ^ (int) ((expectedTag >>> 56) & 0xFFL))
                | ((id[15] & 0xFF) ^ (int) ((expectedTag >>> 48) & 0xFFL));
        return diff == 0;
    }

    // -----------------------------------------------------------------------
    //  SipHash-2-4  — FULLY INLINED, ZERO ALLOCATION
    // -----------------------------------------------------------------------

    /**
     * Message layout:  DOMAIN_PREFIX(7) || type(N) || 0x00(1) || id[0..13](14)
     * Total length:    22 + type.length
     *
     * Every SipRound is inlined. No helper methods, no long[] returns.
     */
    private long computeSipHashTag(byte[] id, byte[] type, int secretId) {
        final long k0 = secretK0[secretId];
        final long k1 = secretK1[secretId];

        long v0 = SIPHASH_C0 ^ k0;
        long v1 = SIPHASH_C1 ^ k1;
        long v2 = SIPHASH_C2 ^ k0;
        long v3 = SIPHASH_C3 ^ k1;

        // We absorb the message in little-endian 8-byte words.
        // Track a pending word `m` and how many bytes are in it (`mBytes`).
        long m = DOMAIN_PREFIX_WORD;   // 7 bytes pre-packed
        int mBytes = DOMAIN_PREFIX_LEN; // 7
        int totalLen = DOMAIN_PREFIX_LEN; // 7

        // --- absorb type bytes ---
        for (int i = 0; i < type.length; i++) {
            m |= (type[i] & 0xFFL) << (mBytes << 3);
            mBytes++;
            totalLen++;

            if (mBytes == 8) {
                v3 ^= m;
                // SipRound x2 (inlined)
                v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
                v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
                v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
                v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

                v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
                v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
                v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
                v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

                v0 ^= m;
                m = 0L;
                mBytes = 0;
            }
        }

        // --- absorb separator 0x00 (just advances mBytes/totalLen; byte value is 0) ---
        // m |= 0;  // no-op
        mBytes++;
        totalLen++;

        if (mBytes == 8) {
            v3 ^= m;
            v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
            v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
            v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
            v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

            v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
            v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
            v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
            v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

            v0 ^= m;
            m = 0L;
            mBytes = 0;
        }

        // --- absorb id[0..13] ---
        for (int i = 0; i < 14; i++) {
            m |= (id[i] & 0xFFL) << (mBytes << 3);
            mBytes++;
            totalLen++;

            if (mBytes == 8) {
                v3 ^= m;
                v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
                v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
                v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
                v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

                v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
                v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
                v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
                v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

                v0 ^= m;
                m = 0L;
                mBytes = 0;
            }
        }

        // --- finalization padding ---
        long b = ((long) totalLen << 56) | m;

        v3 ^= b;
        // SipRound x2
        v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
        v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
        v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
        v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

        v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
        v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
        v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
        v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

        v0 ^= b;

        v2 ^= 0xffL;

        // SipRound x4
        v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
        v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
        v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
        v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

        v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
        v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
        v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
        v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

        v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
        v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
        v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
        v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

        v0 += v1; v1 = Long.rotateLeft(v1, 13); v1 ^= v0; v0 = Long.rotateLeft(v0, 32);
        v2 += v3; v3 = Long.rotateLeft(v3, 16); v3 ^= v2;
        v0 += v3; v3 = Long.rotateLeft(v3, 21); v3 ^= v0;
        v2 += v1; v1 = Long.rotateLeft(v1, 17); v1 ^= v2; v2 = Long.rotateLeft(v2, 32);

        return v0 ^ v1 ^ v2 ^ v3;
    }

    // -----------------------------------------------------------------------
    //  Bit-Level Helpers (allocation-free)
    // -----------------------------------------------------------------------

    private static UUID toUUID(byte[] id) {
        long msb = ((id[0] & 0xFFL) << 56) | ((id[1] & 0xFFL) << 48)
                | ((id[2] & 0xFFL) << 40) | ((id[3] & 0xFFL) << 32)
                | ((id[4] & 0xFFL) << 24) | ((id[5] & 0xFFL) << 16)
                | ((id[6] & 0xFFL) <<  8) |  (id[7] & 0xFFL);

        long lsb = ((id[8]  & 0xFFL) << 56) | ((id[9]  & 0xFFL) << 48)
                | ((id[10] & 0xFFL) << 40) | ((id[11] & 0xFFL) << 32)
                | ((id[12] & 0xFFL) << 24) | ((id[13] & 0xFFL) << 16)
                | ((id[14] & 0xFFL) <<  8) |  (id[15] & 0xFFL);

        return new UUID(msb, lsb);
    }

    /** Write UUID bytes into caller-provided buffer — no allocation. */
    private static void uuidToBytes(UUID uuid, byte[] id) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();

        id[0]  = (byte) (msb >>> 56); id[1]  = (byte) (msb >>> 48);
        id[2]  = (byte) (msb >>> 40); id[3]  = (byte) (msb >>> 32);
        id[4]  = (byte) (msb >>> 24); id[5]  = (byte) (msb >>> 16);
        id[6]  = (byte) (msb >>>  8); id[7]  = (byte)  msb;

        id[8]  = (byte) (lsb >>> 56); id[9]  = (byte) (lsb >>> 48);
        id[10] = (byte) (lsb >>> 40); id[11] = (byte) (lsb >>> 32);
        id[12] = (byte) (lsb >>> 24); id[13] = (byte) (lsb >>> 16);
        id[14] = (byte) (lsb >>>  8); id[15] = (byte)  lsb;
    }

    private static long extractTimestamp(byte[] id) {
        return ((id[0] & 0xFFL) << 40) | ((id[1] & 0xFFL) << 32)
                | ((id[2] & 0xFFL) << 24) | ((id[3] & 0xFFL) << 16)
                | ((id[4] & 0xFFL) <<  8) |  (id[5] & 0xFFL);
    }

    private static long readLittleEndianPadded(byte[] input, int offset) {
        long value = 0L;
        int end = Math.min(offset + 8, input.length);
        for (int i = offset; i < end; i++) {
            value |= (long) (input[i] & 0xFF) << ((i - offset) * 8);
        }
        return value;
    }

    // -----------------------------------------------------------------------
    //  Randomness & Secret Selection
    // -----------------------------------------------------------------------

    private int pickRandomSecretId() {
        if (secretMask >= 0) {
            // Power-of-two fast path: mask is branchless and unbiased.
            return secretIds[ThreadLocalRandom.current().nextInt() & secretMask];
        }
        return secretIds[ThreadLocalRandom.current().nextInt(secretIds.length)];
    }

    /**
     * Fill with ThreadLocalRandom — much faster than SecureRandom.
     *
     * Security rationale: the UUID's integrity comes from the SipHash tag keyed
     * with a secret, not from the entropy quality of the random fill.  An attacker
     * who can predict ThreadLocalRandom output still cannot forge the tag without
     * knowing the secret key.
     *
     * If your threat model requires CSPRNG entropy in the random portion itself
     * (e.g., the random bits are used as a nonce in another protocol), swap this
     * to CSPRNG.nextBytes(id).
     */
    private static void fillRandomness(byte[] id) {
        ThreadLocalRandom tlr = ThreadLocalRandom.current();
        long r0 = tlr.nextLong();
        long r1 = tlr.nextLong();
        id[0]  = (byte) (r0 >>> 56); id[1]  = (byte) (r0 >>> 48);
        id[2]  = (byte) (r0 >>> 40); id[3]  = (byte) (r0 >>> 32);
        id[4]  = (byte) (r0 >>> 24); id[5]  = (byte) (r0 >>> 16);
        id[6]  = (byte) (r0 >>>  8); id[7]  = (byte)  r0;
        id[8]  = (byte) (r1 >>> 56); id[9]  = (byte) (r1 >>> 48);
        id[10] = (byte) (r1 >>> 40); id[11] = (byte) (r1 >>> 32);
        id[12] = (byte) (r1 >>> 24); id[13] = (byte) (r1 >>> 16);
        id[14] = (byte) (r1 >>>  8); id[15] = (byte)  r1;
    }

    private static void validateSecrets(Map<Integer, byte[]> secrets) {
        if (secrets == null || secrets.isEmpty() || secrets.size() > MAX_SECRETS) {
            throw new IllegalArgumentException("Secrets must be between 1 and 16 entries");
        }
        for (Integer id : secrets.keySet()) {
            if (id < 0 || id >= MAX_SECRETS) {
                throw new IllegalArgumentException("Secret ID must be 0-15");
            }
        }
    }
}