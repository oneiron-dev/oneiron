# Per-crate speed benches (FIX 12573, bench only)

Three auto-discovered `examples/` micro-benches, one per lower recall crate. Each
links ONLY its own crate plus that crate's already-declared dependencies — NEVER
`oneiron` or `oneiron-bench` — which limits the build scope. Build-loop time has not yet been measured.
Bench-only files: they measure public kernels on synthetic inputs and must never
be mistaken for recall, pipeline, or accuracy proof.

## Fleet only — never run on a Mac

Build and run these ONLY on a fleet worker, inside the synced worktree, with the
fleet's warm target directory. Never on a Mac, never on a laptop.

```bash
# Inside the synced worktree on the fleet host (warm target per fleet --who):
: "${CARGO_TARGET_DIR:?Use the target directory exported by the fleet runner}"
# Do not remove this target: warm slots reuse it.

# oneiron-retrieval kernels (links oneiron-retrieval + oneiron-contracts only)
cargo build --locked --release -p oneiron-retrieval --example recall_kernels
"$CARGO_TARGET_DIR/release/examples/recall_kernels"

# oneiron-base tokenizer count (links oneiron-base only)
cargo build --locked --release -p oneiron-base --example tokenizer_count
"$CARGO_TARGET_DIR/release/examples/tokenizer_count"

# oneiron-store vector-row codec (links oneiron-store only)
cargo build --locked --release -p oneiron-store --example vector_row_codec
"$CARGO_TARGET_DIR/release/examples/vector_row_codec"
```

All builds use `--locked`: these benches need NO `Cargo.toml`, `Cargo.lock`,
workspace-member, dependency, feature, API, or visibility change. `examples/` are
automatic Cargo targets. If a build ever demands a lock or manifest change,
stop: the bench has drifted out of its zero-seam contract.

## What each bench covers (real public kernels only)

| Bench | Crate | Kernels (exact public symbols) | Defaults |
|---|---|---|---|
| `recall_kernels` | `oneiron-retrieval` | `distance::cosine_similarity`, `distance::PreparedCosine::new` + `distance`, `fusion::sort_scored_entities_desc`, `fusion::fuse_ranked_lists` (list length = public `FUSION_LIST_LENGTH`); ids via checked public `EntityId::from_bytes` | repeats=3, dims=128, candidates=512, lists=4 |
| `tokenizer_count` | `oneiron-base` | `tokenizer::count_context_pack_tokens` (default O200k counter) | repeats=3, records=256, words-per-record=64 |
| `vector_row_codec` | `oneiron-store` | `vector_row::encode_vector_row_v1`, `vector_row::decode_vector_row` | repeats=3, dims=128, rows=512 |

Defaults are central constants at the top of each file (`DEFAULT_REPEATS = 3` in
all three) and every run echoes its effective config. CLI parsing is deliberately
minimal (one flag parser per file, no shared harness): unknown flags and
non-positive integers exit 2 with usage. Integer parsing rejects invalid CLI; it
is NOT a product admission gate and sets no engine caps or policy.

## Output contract

Every run prints:

- `config corpus=synthetic turns=0 messages=0 claims=0 ...` — these are kernel
  vectors and generated record-strings, NOT the 457-turn corpus.
- One line per kernel per repeat with actual `ops`, `items`, `fp_bytes`,
  dimensions/counts/bytes, `batch_ms`, `ms_per_op`, and `pct_of_1ms`.
- `fingerprint_fnv1a64=<16 hex>` — explicit FNV-1a 64 over the ACTUAL output
  bytes (score bits, id bytes in order, counts, encoded bytes, decoded `f32`
  bits) of every repeat in order. Stable across runs and versions (NOT
  `DefaultHasher`). Fingerprinting happens AFTER the timer stops; `black_box`
  shields kernel inputs/outputs inside the timed loop.

Percent-of-1ms-SoL is `100 * 1ms / ms_per_op` (NOT inverted). Compare runs with
the same CLI flags, compiler, CPU target and host conditions. The aggregate
fingerprint includes every repeat, so changing `--repeats` changes it too.
Floating-point output can differ with the CPU or compiler even though the hash
algorithm is fixed. A code change keeps its win only if time drops AND the
fingerprint is unchanged.

Timings plus fingerprint ONLY: no correctness assertions, no test suite, no
speed-win claim. No measured speed or build-time wins are claimed by this pack.

## What these benches explicitly do NOT cover (NOT split / PART)

Full-`oneiron` stages are `pub(crate)` or Vault/store/txn-bound and CANNOT link
per-crate without a future split (see the s14 bench MAP for the full inventory):

- BM25 posting walk + scoring (`oneiron::bm25`, `pub(crate)`).
- HNSW graph search (`oneiron::hnsw`, `pub(crate)`).
- The retrieval pipeline itself (`Vault::query() -> PipelineBuilder`), census,
  temporal widen/execute, hydrate (claim decode + surfaceability), and the
  `scoped_read` access gate — all Vault-bound in `oneiron`.
- `PreparedCosine::similarity` (deliberately `pub(super)`); the bench uses the
  public `distance` method instead.

Micro-kernel SoL% is a per-op yardstick ONLY: it is NOT end-to-end recall speed
and cannot stand in for recall accuracy, BM25/HNSW/Vault/gate/hydrate behaviour,
or full-pipeline proof. Synthetic inputs, CLI flags, and fingerprints can never
substitute for the real corpus or the real pipeline.

## Winner confirmation (unchanged)

The full 457-turn bench confirms every per-crate winner before any READY:
`oneiron-bench load corpus-recall` plus the kel six-reader A/B with the pybench
reader-equality gate. Per-crate benches are inner-loop instruments only, never a
READY gate by themselves.

## Fixture hygiene (hard rules)

- Inputs are deterministic integer arithmetic with power-of-two scaling (counter
  multiples modulo 1024/64/2048, divided by 512/8/16): no RNG state, no
  machine-dependent seeds, no transcendentals, bit-identical on every machine.
- NEVER bake private evaluation text, prompts, personas, corpus passages, or
  `l15s-inputs/` fixtures into these benches. The tokenizer bench generates bland
  `fieldN=` records from a fixed generic word list; that is the whole vocabulary.
- No production code exists solely for these benches, and no bench-only symbol
  may leak into a production API.
