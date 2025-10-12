package eu.davide.tid;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

class TidTest {

    private Tid tid;

    @BeforeEach
    void setUp() {
        // single secret at id=0, deterministic enough for sanity checks
        tid = new Tid(Map.of(0, "topSecret"));
    }

    private static Map<Integer,String> buildSecrets(int count) {
        return java.util.stream.IntStream.range(0, count)
                .boxed()
                .collect(java.util.stream.Collectors.toMap(i -> i, i -> "secret" + i));
    }

    @Test
    void constructor_rejectsTooManySecrets() {
        Map<Integer,String> secrets = buildSecrets(Tid.MAX_SECRETS + 1);
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new Tid(secrets, null, null));
        assertEquals("Too many secrets", ex.getMessage());
    }

    @Test
    void constructor_rejectsNegativeSecretId() {
        Map<Integer,String> secrets = Map.of(-1, "foo");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new Tid(secrets, null, null));
        assertTrue(ex.getMessage().contains("Secret id OOB"), "message should mention OOB");
    }

    @Test
    void constructor_rejectsSecretIdOutOfRange() {
        Map<Integer,String> secrets = Map.of(Tid.MAX_SECRETS, "foo");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                () -> new Tid(secrets, null, null));
        assertTrue(ex.getMessage().contains("Secret id OOB"), "message should mention OOB");
    }

    @Test
    void constructor_acceptSecrets() {
        Map<Integer,String> secrets = buildSecrets(Tid.MAX_SECRETS);
        assertDoesNotThrow(() -> new Tid(secrets, null, null));
    }


    //--- generate(...) input validation -------------------------------------------

    @Test
    void generate_nullType_throwsNullPointer() {
        assertThrows(NullPointerException.class,
                () -> tid.generate(null, Tid.Mode.RANDOM, 1),
                "Expected NPE when type is null");
    }

    @Test
    void generate_typeTooLong_throwsIllegalArgument() {
        String longType = "x".repeat(256);
        assertThrows(IllegalArgumentException.class,
                () -> tid.generate(longType, Tid.Mode.RANDOM, 1),
                "Expected IAE when type length > 255");
    }

    @Test
    void generate_nullMode_throwsNullPointer() {
        assertThrows(NullPointerException.class,
                () -> tid.generate("user", null, 1),
                "Expected NPE when mode is null");
    }

    @Test
    void generate_invalidTagLen_throwsIllegalArgument() {
        assertAll(
                () -> assertThrows(IllegalArgumentException.class,
                        () -> tid.generate("user", Tid.Mode.RANDOM, 0),
                        "Expected IAE when tagBytes is 0"),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> tid.generate("user", Tid.Mode.TIME_SORTED, 3),
                        "Expected IAE when tagBytes is 3"),
                () -> assertThrows(IllegalArgumentException.class,
                        () -> tid.generate("user", Tid.Mode.RANDOM, 5),
                        "Expected IAE when tagBytes is 5")
        );
    }

    //--- decode(...) input validation ---------------------------------------------

    @Test
    void decode_nullUuid_throwsNullPointer() {
        assertThrows(NullPointerException.class,
                () -> tid.decode(null, "user"),
                "Expected NPE when uuid is null");
    }

    @Test
    void decode_nullExpectedType_throwsNullPointer() {
        UUID u = UUID.randomUUID();
        assertThrows(NullPointerException.class,
                () -> tid.decode(u, null),
                "Expected NPE when expectedType is null");
    }

    @Test
    void decode_expectedTypeTooLong_throwsIllegalArgument() {
        UUID u = UUID.randomUUID();
        String longType = "y".repeat(256);
        assertThrows(IllegalArgumentException.class,
                () -> tid.decode(u, longType),
                "Expected IAE when expectedType length > 255");
    }

    //--- generate + decode round-trip sanity check --------------------------------

    @Test
    void generateDecode_roundTripSucceeds() {
        UUID u = tid.generate("order", Tid.Mode.TIME_SORTED, 1);
        Tid.TidInfo info = tid.decode(u, "order");
        assertTrue(info.validTag(), "Verification tag should be valid");
        assertTrue(info.typeMatches(), "Type should match");
        assertNotNull(info, "Decoded info should not be null");
    }

    @Test
    void generateDecode_allValidCombinationsRoundTrip() {
        // three representative type values: empty, normal, max-length
        String empty     = "";
        String normal    = "customer";
        String maxLength = "x".repeat(255);

        String[] types = { empty, normal, maxLength };
        for (int i = 0; i < 1000; i++) {
            for (String type : types) {
                for (Tid.Mode mode : Tid.Mode.values()) {
                    for (int tagBytes : new int[]{1, 2}) {
                        UUID uuid = tid.generate(type, mode, tagBytes);
                        Tid.TidInfo info = tid.decode(uuid, type);

                        // tag must validate
                        assertTrue(info.validTag(),
                                () -> "validTag failed for type=" + type
                                        + ", mode=" + mode + ", tagBytes=" + tagBytes);

                        // type match
                        assertTrue(info.typeMatches(),
                                () -> "typeMatches failed for type=" + type
                                        + ", mode=" + mode + ", tagBytes=" + tagBytes);

                        // version
                        assertEquals(1, info.version(),
                                () -> "version wrong for type=" + type
                                        + ", mode=" + mode + ", tagBytes=" + tagBytes);

                        // mode
                        assertEquals(mode, info.mode(),
                                () -> "mode mismatch for type=" + type
                                        + ", mode=" + mode + ", tagBytes=" + tagBytes);

                        // timestamp semantics
                        if (mode == Tid.Mode.TIME_SORTED) {
                            assertTrue(info.timestamp() > 0,
                                    () -> "timestamp not positive for TIME_SORTED");
                        } else {
                            assertEquals(0L, info.timestamp(),
                                    () -> "timestamp not zero for RANDOM");
                        }
                    }
                }
            }
        }
    }

    @Test
    void generateDecode_perf() {
        final int TYPES   = 3 * Tid.Mode.values().length * 2; // 3 types * 2 modes * 2 tag sizes
        final int ITER    = 10_000;
        final int TOTAL   = ITER * TYPES;

        String empty     = "";
        String normal    = "customer";
        String maxLength = "x".repeat(255);
        String[] types   = { empty, normal, maxLength };
        int[] tagLens    = { 1, 2 };

        // Warm-up JIT
        for (int i = 0; i < 5000; i++) {
            for (String t : types)
                for (Tid.Mode m : Tid.Mode.values())
                    for (int s : tagLens) {
                        tid.decode(tid.generate(t, m, s), t);
                    }
        }

        long start = System.nanoTime();
        for (int i = 0; i < ITER; i++) {
            for (String t : types) {
                for (Tid.Mode m : Tid.Mode.values()) {
                    for (int s : tagLens) {
                        Tid.TidInfo info = tid.decode(tid.generate(t, m, s), t);
                        if (!info.validTag()) throw new AssertionError("Bad tag");
                    }
                }
            }
        }
        long end = System.nanoTime();

        double avgMicros = (end - start) / 1_000.0 / TOTAL;
        System.out.printf("Average roundtrip: %.3f µs%n", avgMicros);
    }
}
