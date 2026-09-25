# Android embedded engine

`EmbeddedVault` owns the same `oneiron::Vault` core through four JNI hooks.
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

The Android CI leg builds `aarch64-linux-android` with NDK 27.2.12479018 and
API 26, packages the `.so`, then runs the Kotlin open/put/get/reopen test on an
API35 arm64 emulator. Aarch64 provides NEON. The Rust crate also has a native
core round-trip test (`cargo test -p oneiron-android`); this is not a substitute
for the Android instrumentation result.

Canon: `oneiron/core/oneiron-arch-0019-oneiron-db-v1.md` (embedded
same-core deployment); the generated docs mirror remains read-only.

## Native-host Kotlin proof

The adapter is also plain JVM Kotlin. Compile `kotlin/src/main/kotlin/org/oneiron/EmbeddedVault.kt`
and `kotlin/tools/JniSmoke.kt` with `kotlinc -include-runtime -d smoke.jar`. Run:

```sh
cargo build -p oneiron-android
java -Djava.library.path=target/debug -jar smoke.jar /absolute/scratch/vault
```

This proves the JNI field ownership, byte-array boundary, open/put/get/reopen,
invalid-id refusal and idempotent close through the shipped Kotlin surface.
It does **not** replace the Android NDK build and emulator instrumentation leg.
