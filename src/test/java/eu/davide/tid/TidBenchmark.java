package eu.davide.tid;


import org.openjdk.jmh.annotations.*;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;


@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@State(Scope.Thread)
@Fork(1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class TidBenchmark
{

    @Setup
    public void setup()
    {
        tid = new Tid(Map.of(0, "static-secret-for-benchmarking"));
        type = "user".getBytes(StandardCharsets.UTF_8);
        testUuid = tid.generate(type, Tid.Mode.TIME_SORTED);
    }


    @Benchmark
    public UUID benchGenerate()
    {
        return tid.generate(type, Tid.Mode.TIME_SORTED);
    }


    @Benchmark
    public Tid.TidInfo benchDecode()
    {
        return tid.decode(testUuid, type);
    }
    private Tid tid;
    private byte[] type;
    private UUID testUuid;

}