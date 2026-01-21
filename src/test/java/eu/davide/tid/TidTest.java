package eu.davide.tid;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.junit.jupiter.api.Assertions.*;

class TidTest {

    private Tid tid;
    private static final byte[] TYPE_USER = "user".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TYPE_DOC = "document".getBytes(StandardCharsets.UTF_8);

    @BeforeEach
    void setUp() {
        // Single secret for simple testing
        tid = new Tid(Map.of(0, "topSecret".getBytes(StandardCharsets.UTF_8)));
    }

    private static Map<Integer, byte[]> buildSecrets(int count) {
        return IntStream.range(0, count)
                .boxed()
                .collect(Collectors.toMap(i -> i, i -> ("secret" + i).getBytes(StandardCharsets.UTF_8)));
    }

    // --- Constructor Logic ---

    @Test
    void constructor_rejectsTooManySecrets() {
        Map<Integer, byte[]> secrets = buildSecrets(17);
        assertThrows(IllegalArgumentException.class, () -> new Tid(secrets));
    }

    @Test
    void constructor_rejectsInvalidSecretIds() {
        assertThrows(IllegalArgumentException.class, () -> new Tid(Map.of(-1, "foo".getBytes(StandardCharsets.UTF_8))));
        assertThrows(IllegalArgumentException.class, () -> new Tid(Map.of(16, "foo".getBytes(StandardCharsets.UTF_8))));
    }

    // --- RFC Compliance & Logic ---

    @Test
    void generate_producesValidRfcUuids() {
        UUID v7 = tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED);
        UUID v4 = tid.generate(TYPE_USER, Tid.Mode.RANDOM);

        assertEquals(7, v7.version(), "Should be UUIDv7");
        assertEquals(4, v4.version(), "Should be UUIDv4");
        assertEquals(2, v7.variant(), "Should be RFC 4122 variant");
    }

    @Test
    void decode_detectsTamperedType() {
        UUID u = tid.generate(TYPE_USER, Tid.Mode.RANDOM);
        Tid.TidInfo info = tid.decode(u, TYPE_DOC); // Expected doc, but it's a user ID

        assertFalse(info.isValid(), "Tag should be invalid when type mismatches");
    }

    @Test
    void decode_detectsTamperedBits() {
        UUID u = tid.generate(TYPE_USER, Tid.Mode.RANDOM);
        // Flip one bit in the random payload (byte 10)
        long lsb = u.getLeastSignificantBits() ^ 0x01L;
        UUID tampered = new UUID(u.getMostSignificantBits(), lsb);

        Tid.TidInfo info = tid.decode(tampered, TYPE_USER);
        assertFalse(info.isValid(), "Tag should fail if ID bits are tampered");
    }

    @Test
    void roundTrip_preservesMetadata() {
        byte[] customType = "order".getBytes(StandardCharsets.UTF_8);
        UUID u = tid.generate(customType, Tid.Mode.TIME_SORTED);

        Tid.TidInfo info = tid.decode(u, customType);

        assertTrue(info.isValid());
        assertEquals(Tid.Mode.TIME_SORTED, info.mode());
        assertEquals(0, info.protoVersion());
        assertTrue(info.timestamp() > 0);
    }

    @Test
    void timeSorted_isMonotonic() throws InterruptedException {
        UUID u1 = tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED);
        Thread.sleep(2);
        UUID u2 = tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED);

        assertTrue(u1.compareTo(u2) < 0, "UUIDv7 should be naturally sortable");
    }

    // --- Performance Sanity ---

    @Test
    void perf_check() {
        int iterations = 100_000;
        // Warmup
        for (int i = 0; i < 10_000; i++) {
            tid.decode(tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED), TYPE_USER);
        }

        long start = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            UUID u = tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED);
            Tid.TidInfo info = tid.decode(u, TYPE_USER);
            if (!info.isValid()) fail();
        }
        long end = System.nanoTime();

        double avg = (end - start) / (double) iterations;
        System.out.printf("Average Tid Roundtrip: %.2f ns%n", avg);
        // Usually hits < 500 ns on decent hardware
        assertTrue(avg < 2000, "Should be sub-2-microsecond");
    }
}