/*
 * Copyright (c) 2025 Davide Tonin
 * Licensed under the Apache License, Version 2.0: https://opensource.org/license/apache-2-0
 */

package eu.davide.tid;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * Generates and decodes self-describing Tid (Tagged ID) identifiers with embedded payload, mode,
 * verification tag-length metadata, and footer flag. Mode and tag length are specified per-ID.
 * Structure (big-endian):
 *   [0...N] timestamp or random (6 bytes if TIME_SORTED),
 *   random bytes,
 *   typeId (1 byte),
 *   infoByte (1 byte: 4 bits secretId, 3 bits version, 1 bit mode),
 *   verification tag (1 or 2 bytes total, using 7 or 15 effective bits),
 *   footer flag lives in the last byte's LSB: 0 => 1 byte tag (7 bits), 1 => 2 bytes tag (15 bits).
 */
public class Tid {
    static final int MAX_SECRETS = 16;
    private static final int TIMESTAMP_BYTES = 6;
    private static final int MAX_TYPE_LENGTH = 255;
    private static final int VERSION = 1;
    private static final SecureRandom SR = new SecureRandom();

    // Thread-local reusable buffers
    private static final ThreadLocal<byte[]> ID_BUF  = ThreadLocal.withInitial(() -> new byte[16]);
    // Worst-case randomness when RANDOM mode and 1-byte tag: 16 - 0 - 2 - 1 = 13
    private static final ThreadLocal<byte[]> RND_BUF = ThreadLocal.withInitial(() -> new byte[13]);

    private static final Map<String,Byte> TYPE_CRC_CACHE = new ConcurrentHashMap<>();

    /** Provides current time in millis for deterministic tests */
    @FunctionalInterface public interface TimeProvider { long nowMillis(); }
    /** Chooses secretId for tagging for deterministic tests */
    @FunctionalInterface public interface SecretProvider { int choose(int[] available); }

    private static final ThreadLocal<MessageDigest> TL_MD = ThreadLocal.withInitial(() -> {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (Exception e) { throw new IllegalStateException(e); }
    });

    /** Mode per ID: TIME_SORTED embeds timestamp prefix; RANDOM uses full randomness */
    public enum Mode {
        RANDOM(0), TIME_SORTED(1);
        private final int bit;
        Mode(int bit) { this.bit = bit; }
        public int bit() { return bit; }
        public static Mode fromBit(int b) { return b == 1 ? TIME_SORTED : RANDOM; }
    }

    private final int[] secretIds;
    private final TimeProvider timeProvider;
    private final SecretProvider secretProvider;
    private final byte[][] secretBytes;

    /**
     * Result of decode, includes extracted mode, version, and dynamic tag length.
     */
    public record TidInfo(
            boolean validTag,
            boolean typeMatches,
            long timestamp,
            int secretId,
            Mode mode,
            int version
    ) {}

    /**
     * Constructs Tid with injectable providers for deterministic testing.
     * @param secrets map of secretId->secret
     * @param timeProvider to supply current time (System::currentTimeMillis if null)
     * @param secretProvider to choose secretId (random if null)
     */
    public Tid(
            Map<Integer,String> secrets,
            TimeProvider timeProvider,
            SecretProvider secretProvider
    ) {
        if (secrets.size() > MAX_SECRETS) throw new IllegalArgumentException("Too many secrets");
        secrets.keySet().forEach(i -> { if (i < 0 || i >= MAX_SECRETS) throw new IllegalArgumentException("Secret id OOB:" + i); });

        this.secretIds = secrets.keySet().stream().mapToInt(i -> i).toArray();
        this.timeProvider = timeProvider != null ? timeProvider : System::currentTimeMillis;
        this.secretProvider = secretProvider != null ? secretProvider
                : ids -> ids[ThreadLocalRandom.current().nextInt(ids.length)];

        this.secretBytes = new byte[MAX_SECRETS][];
        for (int id : secretIds) {
            secretBytes[id] = secrets.get(id).getBytes(UTF_8);
        }
    }

    /** Default constructor: uses system time and random secret selection. */
    public Tid(Map<Integer,String> secrets) {
        this(secrets, null, null);
    }

    private static final byte[] CRC8_TABLE = new byte[256];
    static {
        for (int b = 0; b < 256; b++) {
            int crc = b;
            for (int i = 0; i < 8; i++) {
                if ((crc & 0x80) != 0) crc = (crc << 1) ^ 0x07;
                else crc <<= 1;
            }
            CRC8_TABLE[b] = (byte) crc;
        }
    }

    /**
     * Generates a Tid encoded into a UUID.
     * @param type     the type name (e.g. "user", "doc")
     * @param mode     TIME_SORTED or RANDOM
     * @param tagBytes verification tag length in bytes (1 or 2). Effective bits are 7 or 15 because the LSB of the last byte is reserved.
     * @return         UUID containing the packed Tid
     * @throws NullPointerException if type is null
     * @throws IllegalArgumentException if type is longer than 255 chars
     * @throws NullPointerException if mode is null
     * @throws IllegalArgumentException if tagBytes is not 1 or 2
     */
    public UUID generate(String type, Mode mode, int tagBytes) {
        validateGenerateInput(type, mode, tagBytes);

        byte[] id = ID_BUF.get();
        int pos = 0;
        int secretId = secretProvider.choose(secretIds);

        pos = fillTimestamp(id, pos, mode);
        pos = fillRandomness(id, pos, tagBytes);
        pos = fillType(id, pos, type);
        fillInfo(id, pos, secretId, mode);
        fillTag(id, tagBytes, secretId);

        return packUuid(id);
    }

    /**
     * Decodes and validates a Tid stored inside a UUID.
     * Extracts and validates:
     *   - Timestamp (if present)
     *   - Verification tag
     *   - Type ID
     *   - Secret ID
     *   - Version and mode flags
     *
     * @param uuid          the UUID to decode (contains encoded Tid)
     * @param expectedType  the expected type name (e.g., "user", "doc", "file")
     * @return a decoded and validated TidInfo instance
     */
    public TidInfo decode(UUID uuid, String expectedType) {
        validateDecodeInput(uuid, expectedType);

        byte[] id = uuidToBytes(uuid);                              // unpack
        int tagBytes = getTagBytes(id);                             // 1 or 2
        Info info = extractInfo(id, tagBytes);                      // info byte
        boolean typeMatches = typeMatches(id, tagBytes, expectedType);
        long ts = extractTimestamp(id, info);
        boolean validTag = checkTag(id, tagBytes, info);            // compare verification tag

        return new TidInfo(validTag, typeMatches, ts, info.secretId(), info.mode(), info.version());
    }

    /**
     * Compares the computed verification tag against the stored one.
     * The last bit (LSB) of the last byte is a flag for tag length and is ignored in comparison.
     *
     * @param id       the 16-byte buffer containing the stored tag at the end
     * @param tagBytes 1 or 2
     * @param info     parsed info record (contains secretId)
     * @return true if the tag matches
     */
    private boolean checkTag(byte[] id, int tagBytes, Info info) {
        int offset = id.length - tagBytes;

        byte[] expected = digest(id, offset, info.secretId);
        if (tagBytes == 1) {
            // Compare top 7 bits of the last byte
            int exp = (expected[0] & 0xFE);
            int got = (id[15]        & 0xFE);
            return exp == got;
        } else {
            // First byte must match fully, last byte compare top 7 bits
            if (expected[0] != id[14]) return false;
            int exp = (expected[1] & 0xFE);
            int got = (id[15]        & 0xFE);
            return exp == got;
        }
    }

    /**
     * If time-sorted, unpacks a 6-byte big-endian timestamp from bytes [0..5]; otherwise 0.
     */
    private static long extractTimestamp(byte[] id, Info info) {
        if (info.mode == Mode.TIME_SORTED) {
            return ((long)(id[0] & 0xFF) << 40)
                    | ((long)(id[1] & 0xFF) << 32)
                    | ((long)(id[2] & 0xFF) << 24)
                    | ((long)(id[3] & 0xFF) << 16)
                    | ((long)(id[4] & 0xFF) <<  8)
                    |  (long)(id[5] & 0xFF);
        }
        return 0;
    }

    /**
     * Checks if the embedded typeId in the ID buffer matches the expected type.
     * @param id            the 16-byte buffer decoded from the UUID
     * @param tagBytes      verification tag length in bytes (1 or 2)
     * @param expectedType  the expected type string (e.g., "user", "file")
     */
    private static boolean typeMatches(byte[] id, int tagBytes, String expectedType) {
        return (id[14 - tagBytes] == TYPE_CRC_CACHE.computeIfAbsent(expectedType, Tid::crc8));
    }

    /**
     * Extracts the 3-bit version, 1-bit mode, and 4-bit secretId from the info-byte
     * (the byte immediately before the verification tag).
     *
     * @param id       the full 16-byte buffer
     * @param tagBytes verification tag length in bytes (1 or 2)
     */
    private static Info extractInfo(byte[] id, int tagBytes) {
        int raw = id[id.length - tagBytes - 1] & 0xFF;
        Mode mode = Mode.fromBit(raw & 0x01);
        int version = (raw >>> 1) & 0x07;
        int secretId = (raw >>> 4) & 0x0F;
        return new Info(mode, version, secretId);
    }

    /** Convert UUID to 16-byte array using a thread-local buffer. */
    private static byte[] uuidToBytes(UUID uuid) {
        byte[] id = ID_BUF.get();
        putLong(id, 0, uuid.getMostSignificantBits(), 8);
        putLong(id, 8, uuid.getLeastSignificantBits(), 8);
        return id;
    }

    /**
     * Extracts verification tag length from the last bit of the last byte:
     * 0 → 1 byte tag (7 effective bits), 1 → 2 bytes tag (15 effective bits).
     */
    private static int getTagBytes(byte[] id) {
        return ((id[15] & 0x01) + 1);
    }

    /**
     * Compute SHA-256 digest of the first `length` bytes keyed by the secret for `secretId`.
     * Used to derive the verification tag (first one or two bytes, last-bit masked).
     */
    private byte[] digest(byte[] buf, int length, int secretId) {
        MessageDigest md = TL_MD.get();
        md.reset();
        md.update(secretBytes[secretId]);
        md.update(buf, 0, length);
        return md.digest();
    }

    /** Pack a big-endian long into a byte array. */
    private static void putLong(byte[] dest, int off, long v, int bytes) {
        for (int i = 0; i < bytes; i++) {
            dest[off + i] = (byte)(v >>> (8 * (bytes - 1 - i)));
        }
    }

    /** Reads an unsigned big-endian 8-byte integer from a byte array. */
    private static long getLong(byte[] src, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (src[off + i] & 0xFFL);
        }
        return v;
    }

    /** Computes the CRC-8 checksum of a UTF-8 string. */
    private static byte crc8(String input) {
        byte crc = 0;
        byte[] data = input.getBytes(StandardCharsets.UTF_8);
        for (byte b : data) {
            crc = CRC8_TABLE[(crc ^ b) & 0xFF];
        }
        return crc;
    }

    /** Input validation for {@link #generate(String, Mode, int)}. */
    private static void validateGenerateInput(String type, Mode mode, int tagBytes) {
        Objects.requireNonNull(type, "Type cannot be null");
        Objects.requireNonNull(mode, "Mode cannot be null");
        if (type.length() > MAX_TYPE_LENGTH) {
            throw new IllegalArgumentException(
                    "Type cannot be longer than %s characters".formatted(MAX_TYPE_LENGTH));
        }
        if (tagBytes != 1 && tagBytes != 2) {
            throw new IllegalArgumentException("Verification tag length must be 1 or 2 bytes");
        }
    }

    /** Input validation for {@link #decode(UUID, String)}. */
    private static void validateDecodeInput(UUID uuid, String expectedType) {
        Objects.requireNonNull(uuid, "UUID to decode cannot be null");
        Objects.requireNonNull(expectedType, "Expected type cannot be null");
        if (expectedType.length() > MAX_TYPE_LENGTH) {
            throw new IllegalArgumentException(
                    "Expected type cannot be longer than %s characters".formatted(MAX_TYPE_LENGTH));
        }
    }

    /** Writes the current timestamp into the ID buffer if in TIME_SORTED mode. */
    private int fillTimestamp(byte[] id, int pos, Mode mode) {
        if (mode == Mode.TIME_SORTED) {
            long now = timeProvider.nowMillis();
            putLong(id, pos, now, TIMESTAMP_BYTES);
            return pos + TIMESTAMP_BYTES;
        }
        return pos;
    }

    /** Fills the randomness block in the ID buffer. */
    private static int fillRandomness(byte[] id, int pos, int tagBytes) {
        int len = id.length - pos - 2 - tagBytes;
        byte[] buf = RND_BUF.get();
        if (len <= buf.length) {
            SR.nextBytes(buf);
            System.arraycopy(buf, 0, id, pos, len);
        } else {
            // ultra-rare if layout changes; fill directly
            byte[] tmp = new byte[len];
            SR.nextBytes(tmp);
            System.arraycopy(tmp, 0, id, pos, len);
        }
        return pos + len;
    }

    /** Writes the type identifier (CRC-8 of the type string) into the ID buffer. */
    private static int fillType(byte[] id, int pos, String type) {
        id[pos] = crc8Cached(type);
        return pos + 1;
    }

    private static byte crc8Cached(String input) {
        return TYPE_CRC_CACHE.computeIfAbsent(input, Tid::crc8);
    }

    /**
     * Writes the info byte (secretId, version, mode) into the ID buffer.
     * bits 7–4: secretId (4 bits)
     * bits 3–1: protocol version (3 bits)
     * bit 0   : mode bit (1 bit)
     */
    private static void fillInfo(byte[] id, int pos, int secretId, Mode mode) {
        int info = ((secretId & 0x0F) << 4)
                | ((VERSION  & 0x07) << 1)
                | (mode.bit() & 0x01);
        id[pos] = (byte) info;
    }

    /**
     * Appends the verification tag to the ID buffer and sets the length flag.
     * The tag is derived from the keyed digest of the first (16 - tagBytes) bytes and
     * truncated to 1 or 2 bytes. The last byte's LSB encodes tag length: 0 => 1 byte, 1 => 2 bytes.
     * The effective comparison masks out that LSB, so the tag has 7 or 15 effective bits.
     */
    private void fillTag(byte[] id, int tagBytes, int secretId) {
        int tagOffset = id.length - tagBytes;
        byte[] full = digest(id, tagOffset, secretId);

        if (tagBytes == 1) {
            //noinspection PointlessBitwiseExpression
            id[15] = (byte)((full[0] & 0xFE) | 0);
        } else {
            id[14] = full[0];
            id[15] = (byte)((full[1] & 0xFE) | 1);
        }
    }

    /** Packs the 16-byte buffer back into a UUID. */
    private static UUID packUuid(byte[] id) {
        long msb = getLong(id, 0);
        long lsb = getLong(id, 8);
        return new UUID(msb, lsb);
    }

    private record Info(Mode mode, int version, int secretId) {}
}
