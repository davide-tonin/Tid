package eu.davide.tid;


import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;


@DisplayName("Tid")
class TidTest
{

    private static final int MAX_SECRETS = 16;
    private static final int TOO_MANY_SECRETS = 17;
    private static final int PROTO_VERSION = 0;
    private static final int RFC_VARIANT = 2;
    private static final long CLOCK_DRIFT_BUDGET_MS = 2_000L;

    private static final byte[] TYPE_USER = "user".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TYPE_DOC = "document".getBytes(StandardCharsets.UTF_8);
    private static final byte[] TYPE_ORDER = "order".getBytes(StandardCharsets.UTF_8);


    private static Map<Integer, byte[]> buildSecrets(final int count)
    {
        return IntStream.range(0, count)
                .boxed()
                .collect(Collectors.toMap(i -> i, i -> ("secret" + i).getBytes(StandardCharsets.UTF_8)));
    }


    private static void waitUntilNextMillisecond()
    {
        final long currentMillis = System.currentTimeMillis();

        while (System.currentTimeMillis() == currentMillis)
        {
            Thread.onSpinWait();
        }
    }
    private Tid tid;


    @BeforeEach
    void setUp()
    {
        tid = new Tid(Map.of(0, "topSecret".getBytes(StandardCharsets.UTF_8)));
    }


    @Nested
    @DisplayName("constructor")
    class Constructor
    {

        @Test
        @DisplayName("throws IllegalArgumentException when secrets exceed max entries")
        void constructor_throws_when_secrets_exceed_max_entries()
        {
            final Map<Integer, byte[]> secrets = buildSecrets(TOO_MANY_SECRETS);

            assertThatThrownBy(() -> new Tid(secrets))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Secrets must be between 1 and 16 entries");
        }


        @ParameterizedTest(name = "throws for secret id {0}")
        @ValueSource(ints = {-1, MAX_SECRETS})
        @DisplayName("throws IllegalArgumentException for out-of-range secret id")
        void constructor_throws_for_out_of_range_secret_id(final int invalidSecretId)
        {
            final Map<Integer, byte[]> secrets = Map.of(
                    invalidSecretId,
                    "foo".getBytes(StandardCharsets.UTF_8)
            );

            assertThatThrownBy(() -> new Tid(secrets))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Secret ID must be 0-15");
        }

    }


    @Nested
    @DisplayName("generate")
    class Generate
    {

        @Test
        @DisplayName("produces RFC-compliant UUID versions and variant")
        void generate_produces_rfc_compliant_uuid_versions_and_variant()
        {
            final UUID v7 = tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED);
            final UUID v4 = tid.generate(TYPE_USER, Tid.Mode.RANDOM);

            assertThat(v7.version()).isEqualTo(7);
            assertThat(v4.version()).isEqualTo(4);
            assertThat(v7.variant()).isEqualTo(RFC_VARIANT);
        }


        @Test
        @DisplayName("throws NullPointerException for null type")
        void generate_throws_for_null_type()
        {
            assertThatThrownBy(() -> tid.generate(null, Tid.Mode.RANDOM))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage("Type context cannot be null");
        }


        @Test
        @DisplayName("embeds timestamp within drift budget")
        void generate_time_sorted_embeds_timestamp_within_drift_budget()
        {
            final long beforeGenerationMillis = System.currentTimeMillis();
            final UUID generated = tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED);
            final long afterGenerationMillis = System.currentTimeMillis();

            final Tid.TidInfo info = tid.decode(generated, TYPE_USER);

            assertThat(info.isValid()).isTrue();
            assertThat(info.mode()).isEqualTo(Tid.Mode.TIME_SORTED);
            assertThat(info.timestamp())
                    .isBetween(
                            beforeGenerationMillis - CLOCK_DRIFT_BUDGET_MS,
                            afterGenerationMillis + CLOCK_DRIFT_BUDGET_MS
                    );
        }


        @Test
        @DisplayName("is naturally monotonic without sleeps")
        void generate_time_sorted_is_naturally_monotonic_without_sleeps()
        {
            final UUID first = tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED);
            waitUntilNextMillisecond();
            final UUID second = tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED);

            assertThat(first.compareTo(second)).isLessThan(0);
        }

    }


    @Nested
    @DisplayName("decode")
    class Decode
    {

        @Test
        @DisplayName("returns invalid when expected type mismatches")
        void decode_returns_invalid_when_expected_type_mismatches()
        {
            final UUID generated = tid.generate(TYPE_USER, Tid.Mode.RANDOM);

            final Tid.TidInfo info = tid.decode(generated, TYPE_DOC);

            assertThat(info.isValid()).isFalse();
        }


        @Test
        @DisplayName("returns invalid when payload bits are tampered")
        void decode_returns_invalid_when_payload_bits_are_tampered()
        {
            final UUID generated = tid.generate(TYPE_USER, Tid.Mode.RANDOM);
            final long tamperedLsb = generated.getLeastSignificantBits() ^ 0x01L;
            final UUID tampered = new UUID(generated.getMostSignificantBits(), tamperedLsb);

            final Tid.TidInfo info = tid.decode(tampered, TYPE_USER);

            assertThat(info.isValid()).isFalse();
        }


        @Test
        @DisplayName("preserves mode, protocol version and timestamp on round-trip")
        void decode_preserves_mode_protocol_version_and_timestamp_on_round_trip()
        {
            final UUID generated = tid.generate(TYPE_ORDER, Tid.Mode.TIME_SORTED);

            final Tid.TidInfo info = tid.decode(generated, TYPE_ORDER);

            assertThat(info.isValid()).isTrue();
            assertThat(info.mode()).isEqualTo(Tid.Mode.TIME_SORTED);
            assertThat(info.protoVersion()).isEqualTo(PROTO_VERSION);
            assertThat(info.timestamp()).isPositive();
        }


        @Test
        @DisplayName("throws NullPointerException for null uuid")
        void decode_throws_for_null_uuid()
        {
            assertThatThrownBy(() -> tid.decode(null, TYPE_USER))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage("UUID cannot be null");
        }


        @Test
        @DisplayName("throws NullPointerException for null expected type")
        void decode_throws_for_null_expected_type()
        {
            final UUID generated = tid.generate(TYPE_USER, Tid.Mode.RANDOM);

            assertThatThrownBy(() -> tid.decode(generated, null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage("Expected type cannot be null");
        }

    }

}
