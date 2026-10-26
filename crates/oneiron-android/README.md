# Android embedded engine

`EmbeddedVault` owns the same `oneiron::Vault` core through its JNI hooks.
The Kotlin object owns the native handle, serializes calls, and releases it in
`close()`. There is no native process-global vault registry. Engine refusals
become `IllegalStateException`; a missing entity alone returns `null`.

Use the app-private files directory for production vaults. Close each instance
before reopening the same root. Do not mutate `nativeHandle` with reflection.
A phone app opens with `EmbeddedVault(path, DeviceClass.PHONE)`: the class is
the host's to declare, never read off the OS, and `COMPUTER` is the default.
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

Beside `put` and `get`, `delete`, `putEdge`, `edgesOut`/`edgesIn`, `putVector` and
`searchVector` (every hit asked for) cross the same boundary, with 32-character hex ids, and so do
the C ABI's reads: `contextPack(text, vector, limit, format)` (UTF-8 in `json`, `yaml`, `toon`,
`markdown` or `plaintext`), `searchText(query, limit)`, `targets`/`sources(id, kind, type)`,
`subtree(root, maxDepth)` and `ancestors(node)`, each lowered to the same core read. A vault
from `bound(actorKey, session)` writes as that caller through the core's raw caller doors
(OF-063); its `delete` is the owner-only `vault.delete` door, so an id naming no record throws.

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
engine.openConnection().use { socket ->
    socket.send("GET /ws HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer $bearer\r\nconnection: upgrade\r\nupgrade: websocket\r\nsec-websocket-version: 13\r\nsec-websocket-key: $key\r\n\r\n".toByteArray())
    val head = socket.receive()  // the 101, then the server's frames on later receives
}
engine.vault().use { vault -> vault.get("0102030405060708090a0b0c0d0e0f10") }
engine.stop()  // backgrounding: drain, stop every worker, keep the vault open
engine.wake()  // the timer fired: serve again over the same vault, run what is due
engine.close()
```

`request` is one buffered HTTP/1.1 exchange: headers pass through (bring your
own auth), a 4xx/5xx is a reply, and `/ws`, other upgrades and a reply body
over 64 MiB throw. `openConnection()` holds a connection of the app's own
instead: one in-process stream the server serves as a socket's connection,
HTTP/1.1 with upgrades, so `/ws` and streamed replies ride it. `send` writes
bytes, `receive` returns the next bytes the server wrote (at most 64 KiB, empty
once the connection ended) and `close` ends the app's side, returning a
blocked `receive`; a `stop` drains it, so after `wake` open another. `vault()`
shares the engine's open vault and never reopens the path. `artifactRequest` and
`openArtifactConnection()` reach the artifact app (`/a/`) on its own origin, apart from the
API's. An engine failure throws `EngineException`, an `IllegalStateException` whose `code` is
its cause's stable code (`ENGINE_STOPPED`, `ENGINE_CLOSED`, ...), as every binding names it.
Every engine method
blocks: call it from an app thread, never from an `AppHost` callback (the engine calls those on its own threads, and a call
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
