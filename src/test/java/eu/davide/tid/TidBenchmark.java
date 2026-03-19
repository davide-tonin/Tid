package eu.davide.tid;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
@State(Scope.Thread)
@Fork(value = 2)
@Warmup(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
@Measurement(iterations = 8, time = 1, timeUnit = TimeUnit.SECONDS)
public class TidBenchmark {

    private static final int UUID_POOL_SIZE = 1024;

    private Tid tid;
    private byte[] type;
    private UUID[] uuidPool;
    private int index;

    @Setup(Level.Trial)
    public void setup() {
        tid = new Tid(Map.of(
                0, "static-secret-for-benchmarking".getBytes(StandardCharsets.UTF_8)
        ));

        type = "user".getBytes(StandardCharsets.UTF_8);

        uuidPool = new UUID[UUID_POOL_SIZE];
        for (int i = 0; i < UUID_POOL_SIZE; i++) {
            uuidPool[i] = tid.generate(type, Tid.Mode.TIME_SORTED);
        }

        index = 0;
    }

    @Benchmark
    public void benchGenerate(Blackhole bh) {
        bh.consume(tid.generate(type, Tid.Mode.TIME_SORTED));
    }

    @Benchmark
    public void benchDecode(Blackhole bh) {
        UUID uuid = uuidPool[index];
        index = (index + 1) & (UUID_POOL_SIZE - 1);

        bh.consume(tid.decode(uuid, type));
    }
}