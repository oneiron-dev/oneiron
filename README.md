<div align="center">

# oneiron

**Embedded retrieval engine for memory-first applications.**

One binary. One process. Zero network hops.

<br>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/architecture-dark.svg?v=12">
  <source media="(prefers-color-scheme: light)" srcset="./docs/architecture-light.svg?v=12">
  <img alt="oneiron architecture" src="./docs/architecture-light.svg?v=12" width="700">
</picture>

<br>

</div>

## Why

Most retrieval stacks bolt together separate services for vectors, text, and graphs — network hops, consistency gaps, and operational complexity that doesn't belong on a phone. Oneiron runs in-process as a Rust library with C FFI bindings. Every query touches a single LMDB environment with ACID transactions. Embed it on iOS, Android, desktop, or a server.

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/deployment-dark.svg?v=12">
  <source media="(prefers-color-scheme: light)" srcset="./docs/deployment-light.svg?v=12">
  <img alt="oneiron deployment targets" src="./docs/deployment-light.svg?v=12" width="600">
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

## Building

```sh
cargo build --release
cargo test
```

## Upgrade Notes

- `ANALYZER_VERSION = "v2"` changes analyzer-manifest hashes to capture
  Han `whichlang` routing behavior. Existing text indexes built with older
  analyzer manifests must be rebuilt after upgrading; reopen with
  `VaultConfig::skip_text_index_manifest_check = true`, run
  `clear_text_index`, reopen normally, then reindex documents.

## Design

18 LMDB databases per vault. Atomic multi-database writes via `BatchBuilder`. MessagePack entity blobs. Context packing into LLM-ready formats.

<div align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./docs/storage-dark.svg?v=12">
  <source media="(prefers-color-scheme: light)" srcset="./docs/storage-light.svg?v=12">
  <img alt="oneiron storage layout" src="./docs/storage-light.svg?v=12" width="700">
</picture>
</div>

Full details in the design docs:

- [`SCHEMA-DESIGN.md`](./SCHEMA-DESIGN.md) — database layout, key formats, encoding
- [`BUILD-PROMPT.md`](./BUILD-PROMPT.md) — architecture, algorithms, API surface
- [`DEPLOYMENT.md`](./DEPLOYMENT.md) — multi-vault deployment, ML infrastructure

## License

Apache 2.0
