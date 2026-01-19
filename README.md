# Tid (Tagged ID)

## TL;DR -- The Pre-DB Sanity Filter

Tid is a stateless, high-performance identifier that tells you what it
is and whether it belongs to your system before you ever hit your
database.

-   **RFC 9562 Compliant**: Drop-in replacement for UUIDv4 (Random) and
    UUIDv7 (Time-ordered).
-   **Probabilistic Filtering**: Rejects garbage or adversarial spray at
    the edge with a 16-bit cryptographic tag (1/65536 false positive
    rate).
-   **Allocation-Free**: Optimized with ThreadLocal pooling for
    sub-microsecond performance.
-   **Context Bound**: Types (e.g., "user", "order") are baked into the
    tag. No cross-type ID reuse.

------------------------------------------------------------------------

## Structure (UUIDv7 / Time-Sorted Mode)

| Field | Size | Location | Purpose |
|------|------|----------|---------|
| Timestamp | 48 bits | Bytes 0–5 | Millisecond epoch (sortable) |
| Version | 4 bits | Byte 6 (high) | 0111 (v7) or 0100 (v4) |
| SecretId | 4 bits | Byte 6 (low) | Identifies which secret signed this ID |
| Random | 52 bits | Various | Collision resistance |
| Variant | 2 bits | Byte 8 (high) | RFC 4122 Variant (10) |
| ProtoVer | 2 bits | Byte 8 (mid) | Tid internal versioning |
| Verification Tag | 16 bits | Bytes 14–15 | Digest fragment |

------------------------------------------------------------------------

## Usage

### 1. Initialize with Secrets

``` java
static final byte[] TYPE_USER = "user".getBytes(StandardCharsets.UTF_8);

Map<Integer, String> secrets = Map.of(
    0, "alpha-secret-key-high-entropy",
    1, "beta-secret-key-high-entropy"
);

Tid tid = new Tid(secrets);
```

### 2. Generate

``` java
UUID id = tid.generate(TYPE_USER, Tid.Mode.TIME_SORTED);
```

### 3. Decode & Filter

``` java
Tid.TidInfo info = tid.decode(id, TYPE_USER);

if (info.isValid()) {
    System.out.println("Mode: " + info.mode());
    System.out.println("Created: " + info.timestamp());
    System.out.println("Secret Used: " + info.secretId());
}
```

------------------------------------------------------------------------

## Design Principles

-   HMAC-lite construction
-   Constant-time comparison
-   Zero allocation runtime

------------------------------------------------------------------------

## Installation

``` xml
<dependency>
  <groupId>eu.davide</groupId>
  <artifactId>tid</artifactId>
  <version>1.0.0</version>
</dependency>
```

------------------------------------------------------------------------

## License

Licensed under the Apache License 2.0.
