/*
 * Copyright (c) 2025 Davide Tonin
 * Licensed under the Apache License, Version 2.0
 */
package eu.davide.tid;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Tid v2: RFC 9562 compliant (v4/v7) secure identifier.
 * Optimized for zero-allocation generation and cached-byte type validation.
 */
public class Tid {

    private static final int PROTO_VERSION = 0;
    private static final int MAX_SECRETS = 16;
    private static final byte[] DOMAIN_PREFIX = "tid|v2|".getBytes(StandardCharsets.UTF_8);

    private static final ThreadLocal<MessageDigest> DIGEST_POOL = ThreadLocal.withInitial(() -> {
        try { return MessageDigest.getInstance("SHA-256"); }
        catch (Exception e) { throw new IllegalStateException(e); }
    });

    private static final ThreadLocal<byte[]> BUFFER_POOL = ThreadLocal.withInitial(() -> new byte[16]);
    private static final ThreadLocal<byte[]> DECODE_BUFFER_POOL = ThreadLocal.withInitial(() -> new byte[16]);
    private static final SecureRandom CSPRNG = new SecureRandom();

    private final int[] secretIds;
    private final byte[][] secretBytes;

    public enum Mode { RANDOM, TIME_SORTED }

    public record TidInfo(
            boolean isValid,
            long timestamp,
            int secretId,
            Mode mode,
            int protoVersion
    ) {}

    public Tid(Map<Integer, String> secrets) {
        validateSecrets(secrets);
        this.secretIds = secrets.keySet().stream().mapToInt(i -> i).toArray();
        this.secretBytes = new byte[MAX_SECRETS][];
        secrets.forEach((k, v) -> this.secretBytes[k] = v.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generates a secure, tagged UUID.
     * Use cached UTF-8 bytes for 'type' to maximize performance.
     */
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

    /**
     * Decodes and verifies a UUID against an expected type byte array.
     */
    public TidInfo decode(UUID uuid, byte[] expectedType) {
        Objects.requireNonNull(uuid, "UUID cannot be null");
        Objects.requireNonNull(expectedType, "Expected type cannot be null");

        byte[] id = uuidToBytes(uuid);

        int modeAsInt = extractModeAsInt(id);
        int secretId = extractSecretId(id);
        int protoVersion = extractProtoVersion(id);
        Mode mode = determineMode(modeAsInt);

        boolean valid = checkValidity(mode, secretId, expectedType, id);
        long timestamp = (mode == Mode.TIME_SORTED) ? extractTimestamp(id) : 0L;

        return new TidInfo(valid, timestamp, secretId, mode, protoVersion);
    }

    // --- Internal Logic ---

    private void applyStructure(byte[] id, Mode mode) {
        if (mode == Mode.TIME_SORTED) {
            long now = System.currentTimeMillis();
            id[0] = (byte) (now >>> 40);
            id[1] = (byte) (now >>> 32);
            id[2] = (byte) (now >>> 24);
            id[3] = (byte) (now >>> 16);
            id[4] = (byte) (now >>> 8);
            id[5] = (byte) (now);
            id[6] = (byte) ((id[6] & 0x0F) | 0x70); // v7
        } else {
            id[6] = (byte) ((id[6] & 0x0F) | 0x40); // v4
        }
        id[8] = (byte) ((id[8] & 0x3F) | 0x80); // Variant 10
    }

    private void embedMetadata(byte[] id, int secretId) {
        id[6] = (byte) ((id[6] & 0xF0) | (secretId & 0x0F));
        id[8] = (byte) ((id[8] & 0xCF) | ((PROTO_VERSION & 0x03) << 4));
    }

    private void sealWithTag(byte[] id, byte[] type, int secretId) {
        byte[] tag = computeHmacLikeTag(id, type, secretId);
        id[14] = tag[0];
        id[15] = tag[1];
    }

    private boolean checkValidity(Mode mode, int secretId, byte[] expectedType, byte[] id) {
        if (mode == null || secretId < 0 || secretId >= MAX_SECRETS || secretBytes[secretId] == null) return false;
        return verifyTag(id, expectedType, secretId);
    }

    private boolean verifyTag(byte[] id, byte[] expectedType, int secretId) {
        byte[] expected = computeHmacLikeTag(id, expectedType, secretId);
        int result = (id[14] ^ expected[0]) | (id[15] ^ expected[1]);
        return result == 0;
    }

    private byte[] computeHmacLikeTag(byte[] id, byte[] type, int secretId) {
        MessageDigest md = DIGEST_POOL.get();
        md.reset();
        md.update(secretBytes[secretId]);
        md.update(DOMAIN_PREFIX);
        md.update(type);
        md.update((byte) 0x00);
        md.update(id, 0, 14);
        return md.digest();
    }

    // --- Bit-Level Helpers ---

    private UUID toUUID(byte[] id) {
        long msb = ((id[0] & 0xFFL) << 56) | ((id[1] & 0xFFL) << 48) | ((id[2] & 0xFFL) << 40) | ((id[3] & 0xFFL) << 32) |
                ((id[4] & 0xFFL) << 24) | ((id[5] & 0xFFL) << 16) | ((id[6] & 0xFFL) << 8)  | (id[7] & 0xFFL);
        long lsb = ((id[8] & 0xFFL) << 56) | ((id[9] & 0xFFL) << 48) | ((id[10] & 0xFFL) << 40) | ((id[11] & 0xFFL) << 32) |
                ((id[12] & 0xFFL) << 24) | ((id[13] & 0xFFL) << 16) | ((id[14] & 0xFFL) << 8) | (id[15] & 0xFFL);
        return new UUID(msb, lsb);
    }

    private byte[] uuidToBytes(UUID uuid) {
        byte[] id = DECODE_BUFFER_POOL.get();
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        for (int i = 0; i < 8; i++) id[i] = (byte) (msb >>> (56 - i * 8));
        for (int i = 0; i < 8; i++) id[8 + i] = (byte) (lsb >>> (56 - i * 8));
        return id;
    }

    private Mode determineMode(int version) {
        return switch (version) {
            case 4 -> Mode.RANDOM;
            case 7 -> Mode.TIME_SORTED;
            default -> null;
        };
    }

    private long extractTimestamp(byte[] id) {
        long ts = 0;
        for (int i = 0; i < 6; i++) ts = (ts << 8) | (id[i] & 0xFF);
        return ts;
    }

    private int extractModeAsInt(byte[] id) { return (id[6] >>> 4) & 0x0F; }
    private int extractSecretId(byte[] id) { return id[6] & 0x0F; }
    private int extractProtoVersion(byte[] id) { return (id[8] >>> 4) & 0x03; }
    private int pickRandomSecretId() { return secretIds[ThreadLocalRandom.current().nextInt(secretIds.length)]; }
    private void fillRandomness(byte[] id) { CSPRNG.nextBytes(id); }

    private void validateSecrets(Map<Integer, String> secrets) {
        if (secrets == null || secrets.isEmpty() || secrets.size() > MAX_SECRETS)
            throw new IllegalArgumentException("Secrets must be between 1 and 16 entries");
        for (Integer id : secrets.keySet()) if (id < 0 || id >= MAX_SECRETS)
            throw new IllegalArgumentException("Secret ID must be 0-15");
    }
}