/*
 * Copyright (c) 2025 Davide Tonin
 * Licensed under the Apache License, Version 2.0
 */
package eu.davide.tid;


import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;


/**
 Tid v2: RFC 9562 compliant (v4/v7) secure identifier.
 */
public final class Tid
{

    private static final int PROTO_VERSION = 0;
    private static final int MAX_SECRETS = 16;

    private static final int UUID_BYTES = 16;
    private static final int TAG_SOURCE_BYTES = 14;
    private static final int DOMAIN_PREFIX_LEN = 7;

    private static final int IDX_VERSION_SECRET = 6;
    private static final int IDX_VARIANT_PROTO = 8;
    private static final int IDX_TAG_FIRST = 14;
    private static final int IDX_TAG_SECOND = 15;

    private static final int UUID_V4 = 4;
    private static final int UUID_V7 = 7;

    private static final int NIBBLE_SHIFT = 4;
    private static final int MASK_NIBBLE = 0x0F;
    private static final int MASK_KEEP_HIGH_NIBBLE = 0xF0;
    private static final int MASK_CLEAR_VARIANT_BITS = 0x3F;
    private static final int MASK_CLEAR_PROTO_BITS = 0xCF;
    private static final int MASK_PROTO_VERSION = 0x03;

    private static final int BYTE_MASK = 0xFF;
    private static final int TAG_SHIFT_FIRST = 56;
    private static final int TAG_SHIFT_SECOND = 48;

    private static final byte[] DOMAIN_PREFIX = "tid|v2|".getBytes(StandardCharsets.UTF_8);
    private static final long DOMAIN_PREFIX_WORD;

    private static final long SIPHASH_C0 = 0x736f6d6570736575L;
    private static final long SIPHASH_C1 = 0x646f72616e646f6dL;
    private static final long SIPHASH_C2 = 0x6c7967656e657261L;
    private static final long SIPHASH_C3 = 0x7465646279746573L;

    private static final ThreadLocal<byte[]> GENERATE_BUFFER_POOL =
            ThreadLocal.withInitial(() -> new byte[UUID_BYTES]);

    private static final ThreadLocal<byte[]> DECODE_BUFFER_POOL =
            ThreadLocal.withInitial(() -> new byte[UUID_BYTES]);


    public Tid(final Map<Integer, byte[]> secrets)
    {
        validateSecrets(secrets);

        this.secretIds = secrets.keySet()
                .stream()
                .mapToInt(i -> i)
                .toArray();

        this.secretBytes = new byte[MAX_SECRETS][];

        secrets.forEach((secretId, secretValue) ->
        {
            this.secretBytes[secretId] = secretValue;
            this.secretK0[secretId] = readLittleEndianPadded(secretValue, 0);
            this.secretK1[secretId] = readLittleEndianPadded(secretValue, 8);
        });

        final int secretCount = secretIds.length;
        this.secretMask = ((secretCount & (secretCount - 1)) == 0) ? (secretCount - 1) : -1;
    }


    private final int[] secretIds;
    private final byte[][] secretBytes;
    private final long[] secretK0 = new long[MAX_SECRETS];
    private final long[] secretK1 = new long[MAX_SECRETS];
    private final int secretMask;


    public UUID generate(final byte[] type, final Mode mode)
    {
        Objects.requireNonNull(type, "Type context cannot be null");

        final byte[] id = GENERATE_BUFFER_POOL.get();
        final int secretId = pickRandomSecretId();

        fillRandomness(id);
        applyStructure(id, mode);
        embedMetadata(id, secretId);
        sealWithTag(id, type, secretId);

        final UUID generated = toUUID(id);
        return generated;
    }


    public TidInfo decode(final UUID uuid, final byte[] expectedType)
    {
        Objects.requireNonNull(uuid, "UUID cannot be null");
        Objects.requireNonNull(expectedType, "Expected type cannot be null");

        final byte[] id = DECODE_BUFFER_POOL.get();
        uuidToBytes(uuid, id);

        final int modeAsInt = (id[IDX_VERSION_SECRET] >>> NIBBLE_SHIFT) & MASK_NIBBLE;
        final int secretId = id[IDX_VERSION_SECRET] & MASK_NIBBLE;
        final int protoVersion = (id[IDX_VARIANT_PROTO] >>> NIBBLE_SHIFT) & MASK_PROTO_VERSION;

        final Mode mode = (modeAsInt == UUID_V4) ? Mode.RANDOM
                : (modeAsInt == UUID_V7) ? Mode.TIME_SORTED
                : null;

        final boolean valid = (mode != null)
                && (secretId >= 0 && secretId < MAX_SECRETS)
                && (secretBytes[secretId] != null)
                && verifyTag(id, expectedType, secretId);

        final long timestamp = (mode == Mode.TIME_SORTED) ? extractTimestamp(id) : 0L;
        final TidInfo info = new TidInfo(valid, timestamp, secretId, mode, protoVersion);
        return info;
    }


    private static void applyStructure(final byte[] id, final Mode mode)
    {
        if (mode == Mode.TIME_SORTED)
        {
            final long now = System.currentTimeMillis();
            id[0] = (byte) (now >>> 40);
            id[1] = (byte) (now >>> 32);
            id[2] = (byte) (now >>> 24);
            id[3] = (byte) (now >>> 16);
            id[4] = (byte) (now >>> 8);
            id[5] = (byte) now;
            id[IDX_VERSION_SECRET] = (byte) ((id[IDX_VERSION_SECRET] & MASK_NIBBLE) | 0x70);
        } else
        {
            id[IDX_VERSION_SECRET] = (byte) ((id[IDX_VERSION_SECRET] & MASK_NIBBLE) | 0x40);
        }

        id[IDX_VARIANT_PROTO] = (byte) ((id[IDX_VARIANT_PROTO] & MASK_CLEAR_VARIANT_BITS) | 0x80);
    }


    private static void embedMetadata(final byte[] id, final int secretId)
    {
        id[IDX_VERSION_SECRET] = (byte) ((id[IDX_VERSION_SECRET] & MASK_KEEP_HIGH_NIBBLE) | (secretId & MASK_NIBBLE));
        id[IDX_VARIANT_PROTO] = (byte) ((id[IDX_VARIANT_PROTO] & MASK_CLEAR_PROTO_BITS) | ((PROTO_VERSION & MASK_PROTO_VERSION) << NIBBLE_SHIFT));
    }


    private void sealWithTag(final byte[] id, final byte[] type, final int secretId)
    {
        final long tag = computeSipHashTag(id, type, secretId);
        id[IDX_TAG_FIRST] = (byte) (tag >>> TAG_SHIFT_FIRST);
        id[IDX_TAG_SECOND] = (byte) (tag >>> TAG_SHIFT_SECOND);
    }


    private boolean verifyTag(final byte[] id, final byte[] expectedType, final int secretId)
    {
        final long expectedTag = computeSipHashTag(id, expectedType, secretId);
        final int diff = ((id[IDX_TAG_FIRST] & BYTE_MASK) ^ (int) ((expectedTag >>> TAG_SHIFT_FIRST) & 0xFFL))
                | ((id[IDX_TAG_SECOND] & BYTE_MASK) ^ (int) ((expectedTag >>> TAG_SHIFT_SECOND) & 0xFFL));
        return diff == 0;
    }


    /**
     Message layout: DOMAIN_PREFIX(7) || type(N) || 0x00(1) || id[0..13](14).
     */
    private long computeSipHashTag(final byte[] id, final byte[] type, final int secretId)
    {
        final long k0 = secretK0[secretId];
        final long k1 = secretK1[secretId];

        long v0 = SIPHASH_C0 ^ k0;
        long v1 = SIPHASH_C1 ^ k1;
        long v2 = SIPHASH_C2 ^ k0;
        long v3 = SIPHASH_C3 ^ k1;

        long m = DOMAIN_PREFIX_WORD;
        int mBytes = DOMAIN_PREFIX_LEN;
        int totalLen = DOMAIN_PREFIX_LEN;

        for (int i = 0; i < type.length; i++)
        {
            m |= (type[i] & 0xFFL) << (mBytes << 3);
            mBytes++;
            totalLen++;

            if (mBytes == 8)
            {
                v3 ^= m;
                v0 += v1;
                v1 = Long.rotateLeft(v1, 13);
                v1 ^= v0;
                v0 = Long.rotateLeft(v0, 32);
                v2 += v3;
                v3 = Long.rotateLeft(v3, 16);
                v3 ^= v2;
                v0 += v3;
                v3 = Long.rotateLeft(v3, 21);
                v3 ^= v0;
                v2 += v1;
                v1 = Long.rotateLeft(v1, 17);
                v1 ^= v2;
                v2 = Long.rotateLeft(v2, 32);

                v0 += v1;
                v1 = Long.rotateLeft(v1, 13);
                v1 ^= v0;
                v0 = Long.rotateLeft(v0, 32);
                v2 += v3;
                v3 = Long.rotateLeft(v3, 16);
                v3 ^= v2;
                v0 += v3;
                v3 = Long.rotateLeft(v3, 21);
                v3 ^= v0;
                v2 += v1;
                v1 = Long.rotateLeft(v1, 17);
                v1 ^= v2;
                v2 = Long.rotateLeft(v2, 32);

                v0 ^= m;
                m = 0L;
                mBytes = 0;
            }
        }

        mBytes++;
        totalLen++;

        if (mBytes == 8)
        {
            v3 ^= m;
            v0 += v1;
            v1 = Long.rotateLeft(v1, 13);
            v1 ^= v0;
            v0 = Long.rotateLeft(v0, 32);
            v2 += v3;
            v3 = Long.rotateLeft(v3, 16);
            v3 ^= v2;
            v0 += v3;
            v3 = Long.rotateLeft(v3, 21);
            v3 ^= v0;
            v2 += v1;
            v1 = Long.rotateLeft(v1, 17);
            v1 ^= v2;
            v2 = Long.rotateLeft(v2, 32);

            v0 += v1;
            v1 = Long.rotateLeft(v1, 13);
            v1 ^= v0;
            v0 = Long.rotateLeft(v0, 32);
            v2 += v3;
            v3 = Long.rotateLeft(v3, 16);
            v3 ^= v2;
            v0 += v3;
            v3 = Long.rotateLeft(v3, 21);
            v3 ^= v0;
            v2 += v1;
            v1 = Long.rotateLeft(v1, 17);
            v1 ^= v2;
            v2 = Long.rotateLeft(v2, 32);

            v0 ^= m;
            m = 0L;
            mBytes = 0;
        }

        for (int i = 0; i < TAG_SOURCE_BYTES; i++)
        {
            m |= (id[i] & 0xFFL) << (mBytes << 3);
            mBytes++;
            totalLen++;

            if (mBytes == 8)
            {
                v3 ^= m;
                v0 += v1;
                v1 = Long.rotateLeft(v1, 13);
                v1 ^= v0;
                v0 = Long.rotateLeft(v0, 32);
                v2 += v3;
                v3 = Long.rotateLeft(v3, 16);
                v3 ^= v2;
                v0 += v3;
                v3 = Long.rotateLeft(v3, 21);
                v3 ^= v0;
                v2 += v1;
                v1 = Long.rotateLeft(v1, 17);
                v1 ^= v2;
                v2 = Long.rotateLeft(v2, 32);

                v0 += v1;
                v1 = Long.rotateLeft(v1, 13);
                v1 ^= v0;
                v0 = Long.rotateLeft(v0, 32);
                v2 += v3;
                v3 = Long.rotateLeft(v3, 16);
                v3 ^= v2;
                v0 += v3;
                v3 = Long.rotateLeft(v3, 21);
                v3 ^= v0;
                v2 += v1;
                v1 = Long.rotateLeft(v1, 17);
                v1 ^= v2;
                v2 = Long.rotateLeft(v2, 32);

                v0 ^= m;
                m = 0L;
                mBytes = 0;
            }
        }

        final long b = ((long) totalLen << 56) | m;

        v3 ^= b;
        v0 += v1;
        v1 = Long.rotateLeft(v1, 13);
        v1 ^= v0;
        v0 = Long.rotateLeft(v0, 32);
        v2 += v3;
        v3 = Long.rotateLeft(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = Long.rotateLeft(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = Long.rotateLeft(v1, 17);
        v1 ^= v2;
        v2 = Long.rotateLeft(v2, 32);

        v0 += v1;
        v1 = Long.rotateLeft(v1, 13);
        v1 ^= v0;
        v0 = Long.rotateLeft(v0, 32);
        v2 += v3;
        v3 = Long.rotateLeft(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = Long.rotateLeft(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = Long.rotateLeft(v1, 17);
        v1 ^= v2;
        v2 = Long.rotateLeft(v2, 32);

        v0 ^= b;
        v2 ^= 0xffL;

        v0 += v1;
        v1 = Long.rotateLeft(v1, 13);
        v1 ^= v0;
        v0 = Long.rotateLeft(v0, 32);
        v2 += v3;
        v3 = Long.rotateLeft(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = Long.rotateLeft(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = Long.rotateLeft(v1, 17);
        v1 ^= v2;
        v2 = Long.rotateLeft(v2, 32);

        v0 += v1;
        v1 = Long.rotateLeft(v1, 13);
        v1 ^= v0;
        v0 = Long.rotateLeft(v0, 32);
        v2 += v3;
        v3 = Long.rotateLeft(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = Long.rotateLeft(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = Long.rotateLeft(v1, 17);
        v1 ^= v2;
        v2 = Long.rotateLeft(v2, 32);

        v0 += v1;
        v1 = Long.rotateLeft(v1, 13);
        v1 ^= v0;
        v0 = Long.rotateLeft(v0, 32);
        v2 += v3;
        v3 = Long.rotateLeft(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = Long.rotateLeft(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = Long.rotateLeft(v1, 17);
        v1 ^= v2;
        v2 = Long.rotateLeft(v2, 32);

        v0 += v1;
        v1 = Long.rotateLeft(v1, 13);
        v1 ^= v0;
        v0 = Long.rotateLeft(v0, 32);
        v2 += v3;
        v3 = Long.rotateLeft(v3, 16);
        v3 ^= v2;
        v0 += v3;
        v3 = Long.rotateLeft(v3, 21);
        v3 ^= v0;
        v2 += v1;
        v1 = Long.rotateLeft(v1, 17);
        v1 ^= v2;
        v2 = Long.rotateLeft(v2, 32);

        return v0 ^ v1 ^ v2 ^ v3;
    }


    private static UUID toUUID(final byte[] id)
    {
        final long msb = ((id[0] & 0xFFL) << 56) | ((id[1] & 0xFFL) << 48)
                | ((id[2] & 0xFFL) << 40) | ((id[3] & 0xFFL) << 32)
                | ((id[4] & 0xFFL) << 24) | ((id[5] & 0xFFL) << 16)
                | ((id[6] & 0xFFL) << 8) | (id[7] & 0xFFL);

        final long lsb = ((id[8] & 0xFFL) << 56) | ((id[9] & 0xFFL) << 48)
                | ((id[10] & 0xFFL) << 40) | ((id[11] & 0xFFL) << 32)
                | ((id[12] & 0xFFL) << 24) | ((id[13] & 0xFFL) << 16)
                | ((id[14] & 0xFFL) << 8) | (id[15] & 0xFFL);

        final UUID uuid = new UUID(msb, lsb);
        return uuid;
    }


    private static void uuidToBytes(final UUID uuid, final byte[] id)
    {
        final long msb = uuid.getMostSignificantBits();
        final long lsb = uuid.getLeastSignificantBits();

        id[0] = (byte) (msb >>> 56);
        id[1] = (byte) (msb >>> 48);
        id[2] = (byte) (msb >>> 40);
        id[3] = (byte) (msb >>> 32);
        id[4] = (byte) (msb >>> 24);
        id[5] = (byte) (msb >>> 16);
        id[6] = (byte) (msb >>> 8);
        id[7] = (byte) msb;

        id[8] = (byte) (lsb >>> 56);
        id[9] = (byte) (lsb >>> 48);
        id[10] = (byte) (lsb >>> 40);
        id[11] = (byte) (lsb >>> 32);
        id[12] = (byte) (lsb >>> 24);
        id[13] = (byte) (lsb >>> 16);
        id[14] = (byte) (lsb >>> 8);
        id[15] = (byte) lsb;
    }


    private static long extractTimestamp(final byte[] id)
    {
        return ((id[0] & 0xFFL) << 40) | ((id[1] & 0xFFL) << 32)
                | ((id[2] & 0xFFL) << 24) | ((id[3] & 0xFFL) << 16)
                | ((id[4] & 0xFFL) << 8) | (id[5] & 0xFFL);
    }


    private static long readLittleEndianPadded(final byte[] input, final int offset)
    {
        long value = 0L;
        final int end = Math.min(offset + 8, input.length);

        for (int i = offset; i < end; i++)
        {
            value |= (long) (input[i] & BYTE_MASK) << ((i - offset) * 8);
        }

        return value;
    }


    private int pickRandomSecretId()
    {
        if (secretMask >= 0)
        {
            return secretIds[ThreadLocalRandom.current().nextInt() & secretMask];
        }

        return secretIds[ThreadLocalRandom.current().nextInt(secretIds.length)];
    }


    private static void fillRandomness(final byte[] id)
    {
        final ThreadLocalRandom random = ThreadLocalRandom.current();
        final long r0 = random.nextLong();
        final long r1 = random.nextLong();

        id[0] = (byte) (r0 >>> 56);
        id[1] = (byte) (r0 >>> 48);
        id[2] = (byte) (r0 >>> 40);
        id[3] = (byte) (r0 >>> 32);
        id[4] = (byte) (r0 >>> 24);
        id[5] = (byte) (r0 >>> 16);
        id[6] = (byte) (r0 >>> 8);
        id[7] = (byte) r0;

        id[8] = (byte) (r1 >>> 56);
        id[9] = (byte) (r1 >>> 48);
        id[10] = (byte) (r1 >>> 40);
        id[11] = (byte) (r1 >>> 32);
        id[12] = (byte) (r1 >>> 24);
        id[13] = (byte) (r1 >>> 16);
        id[14] = (byte) (r1 >>> 8);
        id[15] = (byte) r1;
    }


    private static void validateSecrets(final Map<Integer, byte[]> secrets)
    {
        if (secrets == null || secrets.isEmpty() || secrets.size() > MAX_SECRETS)
        {
            throw new IllegalArgumentException("Secrets must be between 1 and 16 entries");
        }

        for (final Map.Entry<Integer, byte[]> entry : secrets.entrySet())
        {
            final Integer secretId = entry.getKey();
            final byte[] secretValue = entry.getValue();

            if (secretId < 0 || secretId >= MAX_SECRETS)
            {
                throw new IllegalArgumentException("Secret ID must be 0-15");
            }

            if (secretValue == null)
            {
                throw new IllegalArgumentException("Secret value cannot be null");
            }
        }
    }


    static
    {
        long prefixWord = 0L;

        for (int i = 0; i < DOMAIN_PREFIX_LEN; i++)
        {
            prefixWord |= (DOMAIN_PREFIX[i] & 0xFFL) << (i * 8);
        }

        DOMAIN_PREFIX_WORD = prefixWord;
    }


    public enum Mode
    {

        RANDOM,
        TIME_SORTED
    }


    public record TidInfo(
            boolean isValid,
            long timestamp,
            int secretId,
            Mode mode,
            int protoVersion
    )
    {
    }

}
