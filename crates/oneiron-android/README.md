# Android embedded engine

`EmbeddedVault` owns the same `oneiron::Vault` core through its JNI hooks.
The Kotlin object owns the native handle, serializes calls, and releases it in
`close()`. There is no native process-global vault registry. Engine refusals
become `IllegalStateException`; a missing entity alone returns `null`.

Use the app-private files directory for production vaults. Close each instance
before reopening the same root. Do not mutate `nativeHandle` with reflection.
The engine checks each body against its kind. Kind 4 is a conversation, and its
body must be a MessagePack map (`ConversationBody`, every field optional).

```kotlin
// MessagePack {"title": "notes"}: a fixmap of one fixstr key and one fixstr value.
val body = byteArrayOf(0x81.toByte(), 0xa5.toByte()) + "title".toByteArray() +
    byteArrayOf(0xa5.toByte()) + "notes".toByteArray()
EmbeddedVault(context.filesDir.resolve("memory").absolutePath).use { vault ->
    vault.put("0102030405060708090a0b0c0d0e0f10", 4, 1, body)
    check(vault.get("0102030405060708090a0b0c0d0e0f10") != null)
}
```

The Android workflow (`.github/workflows/android-embedded.yml`) builds
`aarch64-linux-android` with NDK 27.2.12479018 and API 26, packages the `.so`,
then runs the Kotlin open/put/get/reopen instrumentation test
(`kotlin/src/androidTest/kotlin/org/oneiron/EmbeddedVaultTest.kt`) on an API 35
arm64 emulator. Aarch64 provides NEON. The Rust crate has no Rust tests of its
own; that instrumentation test is the only on-device check.

Canon: `oneiron/core/oneiron-arch-0019-oneiron-db-v1.md` (embedded
same-core deployment); the generated docs mirror remains read-only.

## Embedded engine

`EmbeddedEngine` runs the full server `oneiron serve` runs inside the app's
process (OF-237), next to the plain `EmbeddedVault(path)`, which stays a vault
with no server. The native library carries it only when built with
`--features engine` (`cargo build -p oneiron-android --features engine`); the
default build, the one the Android workflow makes, is the plain vault alone. Its config is the one `oneiron serve --config <configFile>`
resolves for the path, with `dimensions` when it is not 0; a `memoryBytes` or
`cpuMillisPerSecond` of 0 is unbounded. The app implements `AppHost`:
`keychain(name)` returns the secret's bytes or `null`, `scheduleWake(atUnixMs)`
arms or clears (`null`) the app's timer, and `ready()` reports the server up.

```kotlin
val engine = EmbeddedEngine(context.filesDir.resolve("memory").absolutePath, host)
val reply = engine.request("GET", "/.well-known/oneiron", listOf("authorization" to bearer.toByteArray()))
engine.vault().use { vault -> vault.get("0102030405060708090a0b0c0d0e0f10") }
engine.stop()  // backgrounding: drain, stop every worker, keep the vault open
engine.wake()  // the timer fired: serve again over the same vault, run what is due
engine.close()
```

`request` is one buffered HTTP/1.1 exchange: headers pass through (bring your
own auth), a 4xx/5xx is a reply, and `/ws`, other upgrades and a reply body
over 64 MiB throw. `vault()` shares the engine's open vault and never reopens
the path. Every engine method blocks: call it from an app thread, never from
an `AppHost` callback (the engine calls those on its own threads, and a call
back into it throws), and call `close()` before letting it go.

## Native-host Kotlin proof

The adapter is also plain JVM Kotlin. Compile `kotlin/src/main/kotlin/org/oneiron/*.kt`
and `kotlin/tools/JniSmoke.kt` with `kotlinc -include-runtime -d smoke.jar`. Run:

```sh
cargo build -p oneiron-android
java -Djava.library.path=target/debug -jar smoke.jar /absolute/scratch/vault
```

This proves the JNI field ownership, byte-array boundary, open/put/get/reopen,
invalid-id refusal and idempotent close through the shipped Kotlin surface.
It does **not** replace the Android NDK build and emulator instrumentation leg.
