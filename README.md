<div align="center">

# oneiron

**Embedded retrieval engine for memory-first applications.**

One binary. One process. Zero network hops.

<br>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/architecture-dark.svg?v=13">
  <source media="(prefers-color-scheme: light)" srcset="./docs/architecture-light.svg?v=13">
  <img alt="oneiron architecture" src="./docs/architecture-light.svg?v=13" width="700">
</picture>

<br>

</div>

## Why

Most retrieval stacks bolt together separate services for vectors, text, and graphs — network hops, consistency gaps, and operational complexity that doesn't belong on a phone. Oneiron runs in-process as a Rust library with C FFI bindings. Every query touches a single LMDB environment with ACID transactions. Embed it on iOS, Android, desktop, or Node.js — or run the same engine as the `oneiron-server` daemon, locally or hosted.

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/deployment-dark.svg?v=13">
  <source media="(prefers-color-scheme: light)" srcset="./docs/deployment-light.svg?v=13">
  <img alt="oneiron deployment targets" src="./docs/deployment-light.svg?v=13" width="600">
</picture>
</div>

## Signals

| Signal | Engine | What it finds |
|--------|--------|---------------|
| **Vector** | HNSW (flat NSW), SIMD-accelerated | Semantically similar content |
| **Text** | BM25 inverted index | Exact keywords and phrases |
| **Graph** | Personalized PageRank over typed edges | Relationally connected entities |
| **Temporal** | Bi-temporal range indexes | Events by when they happened or were recorded |
| **Phonetic** | Code-based posting lists | Fuzzy matches from voice/ASR misspellings |

Any subset of signals can be combined via **Reciprocal Rank Fusion** with per-signal boosts.

## Quick Start

```rust
use oneiron::{Vault, VaultConfig, EntityId};

let config = VaultConfig::device();
let vault = Vault::open("./my-vault", config)?;

let id = EntityId::now();
vault.put_entity(&id, b"msgpack blob")?;
vault.put_vector(&id, &embedding)?;
```

## Install

Install the local daemon from crates.io after publication:

```sh
cargo install oneiron-server
```

From a checkout:

```sh
cargo install --path crates/oneiron-server
```

One-line install from GitHub:

```sh
curl -fsSL https://raw.githubusercontent.com/oneiron-dev/oneiron/main/deploy/install-oneiron-server.sh | sh
```

Create and inspect the default local vault:

```sh
oneiron-server init ~/.local/share/oneiron/default
oneiron-server doctor ~/.local/share/oneiron/default
```

Run the daemon:

```sh
oneiron-server serve --vault-path ~/.local/share/oneiron/default
```

`serve` also remains the default command for the existing flags:

```sh
oneiron-server --vault-path ~/.local/share/oneiron/default --port 9090
```

The default service vault convention is
`~/.local/share/oneiron/default/`. `oneiron-server serve` reads
`~/.config/oneiron/oneiron.toml` when present; file values are overridden by
`ONEIRON_*` environment variables and then by CLI flags.

## Building

```sh
cargo build --release
cargo nextest run -p oneiron                                # fast tier
cargo nextest run -p oneiron --features sync --profile full # full tier (CI parity)
```

Tests run via [cargo-nextest](https://nexte.st) (`cargo install cargo-nextest`);
profiles and the slow-test tier live in `.config/nextest.toml`. Plain
`cargo test` still works.

## Upgrade Notes

- The protected legacy `/api/*` routes on `oneiron-server` now require an
  **owner-grade** bearer: the configured trust-root secret sent verbatim, or a
  minted token carrying no narrowing claims. A scoped token (`scope=…` and/or
  `principal_ref=…`) authenticates but is refused there with `UNAUTHORIZED`,
  however wide its scopes — those routes read the whole vault under one actor
  ref. (`/api/health` stays unauthenticated.) Scoped tokens remain `/v1`-plane
  instruments and keep working on `/v1/core/*` and the companion control-plane
  routes. Callers that drove `/api/*` with a scoped token must switch to the
  trust-root credential or move to the equivalent `/v1` route.
- `ANALYZER_VERSION = "v2"` changes analyzer-manifest hashes to capture
  Han `whichlang` routing behavior. Existing text indexes built with older
  analyzer manifests must be rebuilt after upgrading; create a `VaultConfig`,
  set `config.skip_text_index_manifest_check = true`, reopen with that config,
  run `MaintenanceBuilder::clear_text_index`, reopen normally, then reindex
  documents.

## Design

28 LMDB databases per vault. Atomic multi-database writes via `BatchBuilder`. MessagePack entity blobs. Context packing into LLM-ready formats.

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/storage-dark.svg?v=13">
  <source media="(prefers-color-scheme: light)" srcset="./docs/storage-light.svg?v=13">
  <img alt="oneiron storage layout" src="./docs/storage-light.svg?v=13" width="700">
</picture>
</div>

Full details in the design docs:

- [`SCHEMA-DESIGN.md`](./SCHEMA-DESIGN.md) — database layout, key formats, encoding
- [`BUILD-PROMPT.md`](./BUILD-PROMPT.md) — architecture, algorithms, API surface
- [`DEPLOYMENT.md`](./DEPLOYMENT.md) — local daemon install, config, and service templates

## License

Apache 2.0
