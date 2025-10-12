# Tid (Tagged ID)

### TL;DR – Why Tid?

It’s a **self-describing ID** that tells you what it is and whether it probably came from your system, without touching the database.

* Embed a **type tag** and **timestamp** directly in a UUID.
* Know if an ID is “mine” or “garbage” instantly.
* Works as a drop-in replacement for `UUID` columns.
* Sorts chronologically when you want.
* Lets you choose between 1-byte (7-bit) or 2-byte (15-bit) verification tags.

**Bro. It’s not authentication.**

---

## Structure

Tid packs the following into 16 bytes (UUID-sized):

| Field | Size | Purpose                                                |
|-------|------|--------------------------------------------------------|
| Timestamp | 6 B | present if Mode == `TIME_SORTED`                       |
| Randomness | variable | fills remaining space                                  |
| TypeId | 1 B | CRC-8 of your type name                                |
| Info | 1 B | version + secretId + mode                              |
| Verification Tag | 1 or 2 B | keyed SHA-256 digest fragment (7 or 15 effective bits) |

---

## Features

* **Self-validation:** quick corruption/ownership check using a keyed digest fragment.
* **Decodable:** timestamp, mode, type, version, secretId — no external lookup.
* **Time-ordered:** `TIME_SORTED` embeds millisecond timestamp for index-friendly sorting.
* **Tunable footprint:** pick 1-byte (more entropy and possible collisions) or 2-byte (stronger check) tags.
* **UUID-compatible:** stored and logged like any other `UUID`.

---

## Installation

### Maven

```xml
<dependency>
  <groupId>eu.davide</groupId>
  <artifactId>tid</artifactId>
  <version>1.0.0</version>
</dependency>
```

### Gradle (Groovy)

```groovy
implementation 'eu.davide:tid:1.0.0'
```

### Gradle (Kotlin)

```kotlin
implementation("eu.davide:tid:1.0.0")
```

---

## Quick Start

```java
Map<Integer,String> secrets = Map.of(
    0, "alpha-secret",
    1, "beta-secret"
);

Tid tid = new Tid(secrets);

UUID id = tid.generate("order", Tid.Mode.TIME_SORTED, 2);

Tid.TidInfo info = tid.decode(id, "order");
// info.validTag(), info.timestamp(), info.mode(), info.secretId(), etc.
```

### 1- or 2-Byte Tags

```java
UUID fast = tid.generate("user", Tid.Mode.RANDOM, 1);   // 7-bit tag
UUID strict = tid.generate("user", Tid.Mode.RANDOM, 2); // 15-bit tag
```

---

## Secret Handling

* Up to 16 secrets (`secretId 0–15`).
* Keep them static for a running system; rotation invalidates old IDs.
* Each thread caches its own SHA-256 instance for speed.

---

## Thread Safety

Everything’s thread-safe.  
All temporary buffers and digests are `ThreadLocal`, no synchronization needed.

---

## Testing

JUnit 5 tests cover:

* Round-trip validity for all modes and tag sizes
* Input-validation edge cases
* Deterministic decoding and timestamp extraction
* Micro-benchmark (10 000 round-trips < 10 ms on modern CPUs)

---

## License

Licensed under the **Apache License 2.0** – see the [LICENSE](LICENSE) file.
