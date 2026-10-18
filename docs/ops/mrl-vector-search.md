# MRL vector search

The text index keeps complete `dimensions`-wide vectors. For an MRL-capable
embedding model, select a measured prefix before creating/opening the vault:

```toml
dimensions = 4
fast_dims = 2
```

These small widths illustrate the wire contract, not a recommended model width.
The same setting is `--fast-dims 2` or `ONEIRON_FAST_DIMS=2`. The engine requires
`1 <= fast_dims < dimensions` and persists the selection in HNSW compatibility.
There is no live prefix mutation: reopening a populated graph with another
prefix fails closed. Omission leaves the default model at full width; no prefix
has been measured for it yet.

All calls below are generated typed SDK/MCP calls and authenticated HTTP POSTs
at `/v1/core/facade/<verb>`:

- `vault.search.vector.config` takes `{}` and returns the open's
  `{dimensions, fast_dims}` in a scoped read result.
- `vault.vectors.put` takes `{entity_ref, vector}`. Only the caller's own owner
  proof authorizes it. It supplies a full-width vector for an existing readable
  record through the existing batch write gate, including model/transform
  checks and revision staging. Its `{entity_ref, dimensions}` receipt means
  accepted, not necessarily indexed: a pending live revision publishes its
  staged inputs at the normal boundary.
- `vault.search.vector` takes `{query_vector, limit, lane?}`. `lane` defaults to
  `ordinary`. A full query refines prefix candidates on the retained full rows.
  A prefix-length query has no full query to rescore and honestly reports
  prefix scoring even on `ordinary`.
- Explicit `lane: "voice_hot"` skips refinement and caps the effective limit at
  the engine's existing speculative fire default (8), below the ordinary search
  ceiling. This is not deadline/call effort and does not simulate ASR. The
  existing `ai.voice.asr.*` family owns utterance triggers, fire budgets and
  warm reuse.

Search returns a scoped read result whose `value` contains `hits`, `lane`,
`effective_limit`, `limit_clamped`, and `refinement`. Each hit carries its
`entity_ref`, `source_revision_ref` (when pinned by the engine), and `score`.
Use that pin when hydrating or citing the retrieved source. `refinement` states
stored, candidate, query and score dimensions and `full_dimension_rescore`.
It is absent when authority prevented the vector channel from running. Full
refinement is exact only within the retrieved beam, not globally exact recall.
Never compare full-space and prefix-space scores or depend on voice tie order.

For the RETRIEVAL-12 journey, supply complete four-dimensional fixture vectors
through `vault.vectors.put` on a vault opened with the two-dimensional prefix.
Search the full query ordinarily to observe tail-based refinement, then declare
`voice_hot` to observe prefix-only evidence. No internal vector writes or test
hooks are needed.
