# oneiron-remote

The shared Rust SDK client behind the `oneiron` npm and PyPI packages and the
UniFFI binding. One `OneironClient` has two backends: `open` binds an
embedded vault, `connect` binds a remote `oneiron-server`, and
`connect_in_process` binds a server this process runs. Every verb enters
through the same dispatcher, so the language bindings convert values and
never branch on the backend.

## Binding surfaces

| Surface | What it runs | Defined in |
|---|---|---|
| `OneironClient` (this crate) | The SDK client over an embedded vault or a served engine. It does not run the served engine's lifecycle. | [`src/lib.rs`](src/lib.rs); embedded backend in [`src/embedded.rs`](src/embedded.rs) |
| N-API `NativeClient` | The private client the `oneiron` npm wrapper holds. Its factories pick the backend. | [`oneiron-napi/src/facade/client.rs`](../oneiron-napi/src/facade/client.rs) |
| N-API `NativeEngine` | The full served engine in process, behind the default-off `engine` feature. `client(key)` serves a credential-bound `NativeClient`. | [`oneiron-napi/src/facade/client/embedded_engine.rs`](../oneiron-napi/src/facade/client/embedded_engine.rs) |
| UniFFI `EmbeddedEngine` | The full served engine in process, behind the `engine` feature. `client(key)` and `local_client()` bind `Oneiron` handles. | [`oneiron-uniffi/src/embedded_engine.rs`](../oneiron-uniffi/src/embedded_engine.rs) |
| PyO3 `NativeEngine` | The optional engine class, behind the `engine` feature. `client(key)` serves a `NativeClient`; it is not the client class itself. | [`oneiron-py/src/embedded_engine.rs`](../oneiron-py/src/embedded_engine.rs) |

Feature-gated rows exist only in builds with `--features engine`.

## Native host limit questions

The Rust host can call `OneironClient::native_limit_questions()` on the original
handle returned by `open` or `open_with_host_root`. Internally opened vaults keep
the latest crossing per engine limit as its configuration key, boundary and exact
`u64` measured value. Reading returns a snapshot without clearing it; no crossing
is `Some` with an empty vector. Same-vault opens share that collector. The actual
embedding width is measured once per shared vault, after the SDK registry lock is
released. A crossing still serves its work; it does not add a refusal or cap.

Attached vaults keep the host's existing question sink untouched and return `None`.
Remote clients and actor, delegated-reader, room or off-record views also return
`None`. This is host metadata, not a facade verb or a remote request; the N-API,
Python, and UniFFI SDK wrappers expose the same getter with the same `None` vs
`Some` contract. It retains no actor identity, query, body, credential or event history.
