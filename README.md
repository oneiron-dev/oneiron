# Oneiron

**Long-context AI memory for agents, built around a local Rust vault.**

## Why

Agents need useful memory across sessions, not just a longer prompt.
They also need to know where a memory came from and which changes are allowed.
Oneiron brings storage, retrieval, provenance, and write policy into one engine
that applications can embed or run as a daemon.

## What works today

- **Local storage.** Each vault uses one LMDB environment. `BatchBuilder` can
  write entities, indexes, and edges in one atomic transaction.
- **Hybrid retrieval.** Vector and BM25F text search, graph expansion, time
  filters, and phonetic matching share a query pipeline. It ranks their candidate
  union with configurable memory metadata.
- **Typed memory and guarded writes.** Claims carry provenance and lifecycle
  state. Actor-write APIs check configured policy and consent before admitting
  claim changes. Policy decisions and scoped reads expose receipts.
- **A server and replication layer.** `oneiron-server` exposes HTTP and WebSocket
  interfaces, including MCP over HTTP. The optional `sync` feature adds
  Loro-based replication.
- **Host-bound agent components.** Dreamer consolidation, durable work, typed
  judgments, and optional JavaScript code execution have Rust implementations.
  Hosts supply the required inference, scheduling, policy, and budget bindings.
  Standard daemon startup does not bind a Dreamer model or code executor.
- **Optional embedding backends.** The daemon can provision a local embedder or
  use a configured endpoint. Generative-model adapters need host runtimes or
  remote providers; they do not bundle model weights.

These are implemented APIs and components. They do not mean that every workflow
in the direction section below is complete.

## Quick Start: the embedded Rust API

This stores and reads a byte payload. It needs no model, embedding, or network
service. It is a low-level storage example, not a typed claim or a retrieval query.

```rust
use oneiron::registry::ENTITY_TYPE_SUMMARY;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let vault = Vault::open("./my-vault", VaultConfig::device())?;

    let id = EntityId::now();
    let payload = b"Hello, Oneiron!";
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    vault.put_entity(
        &id,
        ENTITY_TYPE_SUMMARY,
        TimeRange {
            start: timestamp,
            end: timestamp,
        },
        timestamp,
        payload,
    )?;
    assert_eq!(vault.get(&id)?.as_deref(), Some(payload.as_slice()));
    println!("Stored and read entity {}", id.to_ulid());
    Ok(())
}
```

`Vault::open` can create a vault. On Linux, `Vault::open_existing` opens only an
initialized vault and never creates one.

## Install and build from source

Use the Rust toolchain pinned in [rust-toolchain.toml](./rust-toolchain.toml).
From the repository root:

```sh
cargo build --locked -p oneiron --release
cargo install --locked --path crates/oneiron-server
```

Use a separate, new vault and config for this **development-only** daemon
example. It selects no embedding backend and binds an unauthenticated server
to loopback:

```sh
oneiron-server init ./server-vault --config ./oneiron-server.toml --embedder none
oneiron-server doctor ./server-vault
oneiron-server serve --config ./oneiron-server.toml --host 127.0.0.1 \
  --insecure-allow-unauthenticated
```

This assumes no `ONEIRON_*` overrides. Existing vaults need matching storage,
analyzer, and vector settings. Do not use unauthenticated mode for a shared or
network-facing vault. For authenticated setup, start with
`oneiron-server token bootstrap --help` and the
[authentication reference](./oneiron.skills.md#authentication).
See [DEPLOYMENT.md](./DEPLOYMENT.md) for service templates.
Oneiron is pre-release. This README uses source builds rather than assuming a
published package or release binary.

## Where it is going

These are architecture directions and ongoing work, not a list of finished
features.

1. **Local-first memory with optional hosting.** Keep the same vault model across
   embedding, a local daemon, and an optional hosted peer. Keep local use available
   without requiring a hosted account.
2. **Memory that shows its work.** Connect generated memory and typed judgments
   to their sources, actors, and decision receipts. Keep model advice separate
   from write authority.
3. **Dreamer consolidation.** Build background workflows that reconcile evidence,
   handle conflicting claims, and refresh derived memory between sessions.
4. **One scoped agent API.** Make MCP and sandboxed code mode projections of the
   same typed operations, read scopes, and write gates.
5. **Measured learning and local models.** Use recorded outcomes to improve skills
   and model choices. Explore small local models for Dreamer tasks without sending
   vault text out for that training.

## Crates

| Crate | Role |
|-------|------|
| [oneiron](./crates/oneiron) | Local vault, retrieval, typed memory, and write policy. |
| [oneiron-server](./crates/oneiron-server) | HTTP and WebSocket daemon around the vault. |
| [oneiron-driver](./crates/oneiron-driver) | In-process agent runtime driver. |
| [oneiron-ffi](./crates/oneiron-ffi) | C interface to the engine. |
| [oneiron-napi](./crates/oneiron-napi) | Native Node.js bindings. |
| [oneiron-py](./crates/oneiron-py) | Native Python extension. |
| [oneiron-remote](./crates/oneiron-remote) | Shared embedded and remote SDK backend. |
| [oneiron-uniffi](./crates/oneiron-uniffi) | Definition-only UniFFI interface contract. |
| [oneiron-android](./crates/oneiron-android) | JNI/Kotlin ownership adapter. |
| [oneiron-llm-anthropic](./crates/oneiron-llm-anthropic) | Anthropic Messages adapter. |
| [oneiron-llm-gemini](./crates/oneiron-llm-gemini) | Gemini adapter. |
| [oneiron-llm-openai](./crates/oneiron-llm-openai) | OpenAI-compatible adapter. |
| [oneiron-llm-own-server](./crates/oneiron-llm-own-server) | User-hosted model endpoint adapter. |
| [oneiron-llm-local](./crates/oneiron-llm-local) | Host-supplied in-process model adapter. |
| [oneiron-llm-systemone](./crates/oneiron-llm-systemone) | Remote typed-decision service adapter. |
| [oneiron-image-comfyui](./crates/oneiron-image-comfyui) | ComfyUI image adapter. |
| [oneiron-image-openrouter](./crates/oneiron-image-openrouter) | OpenRouter image adapter. |
| [oneiron-mesh-transport](./crates/oneiron-mesh-transport) | Vault-scoped peer transport. |
| [oneiron-linear](./crates/oneiron-linear) | Linear issue-mirroring adapter. |
| [oneiron-docedit](./crates/oneiron-docedit) | Native document editing and revision support. |
| [oneiron-xlsx-formula](./crates/oneiron-xlsx-formula) | In-process spreadsheet formula recalculation. |
| [oneiron-seal](./crates/oneiron-seal) | PDF signature sealing and verification. |
| [oneiron-guest](./crates/oneiron-guest) | Linux sandbox guest agent and conformance adapter. |
| [oneiron-sandbox-contract](./crates/oneiron-sandbox-contract) | Shared host/guest sandbox protocol rules. |
| [oneiron-vault-contract](./crates/oneiron-vault-contract) | Supervisor-to-vault process protocol and limits. |
| [oneiron-bench](./crates/oneiron-bench) | Benchmark and evaluation harness. |
| [oneiron-macos](./apps/macos/src-tauri) | macOS menu-bar voice recorder embedding the vault. |

The [code map](./docs/CODEMAP.md) links to each crate's modules and source files.

## Storage layout

This diagram matches the vault's named-database manifest. It shows storage
components, not which optional runtime features are enabled.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/storage-dark.svg?v=13">
  <source media="(prefers-color-scheme: light)" srcset="./docs/storage-light.svg?v=13">
  <img alt="Oneiron vault storage layout" src="./docs/storage-light.svg?v=13" width="700">
</picture>

## Development and documentation

Tests use [cargo-nextest](https://nexte.st). The default profile skips the slow
set; the full profile includes it.

```sh
cargo nextest run --locked -p oneiron --all-features
cargo nextest run --locked -p oneiron --features sync,test-hooks --profile full
```

The second command is the narrow sync lane, not the full workspace gate.
[AGENTS.md](./AGENTS.md) covers scoped tests and host requirements.
[WORKFLOW.md](./WORKFLOW.md) covers verification and PRs.
`scripts/verify.sh --list` shows the scripted gate without building.

- [oneiron.skills.md](./oneiron.skills.md): HTTP API reference.
- [UPGRADING.md](./UPGRADING.md): authentication and text-index upgrade notes.
- [MIGRATIONS.md](./MIGRATIONS.md): storage-format decision history.

## License

[Apache-2.0](./LICENSE).
