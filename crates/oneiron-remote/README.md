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
