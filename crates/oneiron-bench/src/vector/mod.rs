//! `vector` subcommand — ARCH-0019 §perf vector benchmark harness (ONE-1120).
//!
//! Contract (ARCH-0019 "oneiron-db benchmark targets",
//! `core/oneiron-arch-0019-oneiron-db-v1`):
//!
//! * Vector search top-10: `< 5ms p50` — "Flat NSW, ef=128".
//! * Recall@10: `> 90%` — "vs brute-force baseline" (float32).
//! * Insert (entity + vector + edges): `< 1ms` — "Single write txn".
//! * Operating point: 10K vault; 1024-dim (device) / 4096-dim (cloud).
//! * HNSW parameters: `m_max_0 = 64`, `ef_construction = 200`,
//!   `ef_search = 128`.
//!
//! Latency / insert targets are GOALS: the harness reports measured values
//! against the target rows but never fails the process on a miss. Recall@10
//! is a hard gate by default (`--no-recall-assert` opts out). Structural
//! invariants always fail closed: every ANN result set must contain exactly
//! `min(10, live)` hits and every hit must be a live (non-deleted) entity —
//! a deleted ID resurfacing after delete-churn is a tombstone leak and fails
//! the run regardless of flags.
//!
//! Determinism: the corpus, query set, churn selections, and churn
//! replacement vectors are all drawn from a single `StdRng` stream seeded by
//! `--seed` (default 42), in a fixed order (corpus IDs+vectors → queries →
//! refresh selection → refresh vectors → delete selection). Same seed ⇒ same
//! corpus ⇒ same recall numbers on a given build. The harness contains no
//! arch-specific code; it runs unchanged on aarch64 (NEON), x86_64
//! (AVX2/scalar), and any other target the engine compiles for.
//!
//! RAM-at-index is reported (raw f32 vector bytes, `data.mdb` disk usage,
//! best-effort process RSS) as the fairness baseline for any future
//! binary-quantization comparison — measurement only, no BQ here.

mod vector_config;
mod vector_report;
mod vector_run;
#[cfg(test)]
mod vector_tests;

#[cfg(test)]
pub(crate) use self::vector_config::ChurnMode;
pub(crate) use self::vector_config::{
    BenchSettings, CONTRACT_EF_CONSTRUCTION, CONTRACT_EF_SEARCH, CONTRACT_M_MAX_0,
    MENTIONS_EDGE_WEIGHT, SEARCH_LIMIT, TARGET_INSERT_P50_MS, TARGET_RECALL_AT_10,
    TARGET_SEARCH_TOP10_P50_MS, parse_args,
};
pub(crate) use self::vector_run::{LatencyStats, RamReport, SearchMeasure, VectorBenchReport, run};
#[cfg(test)]
pub(crate) use self::vector_run::{
    brute_force_top_k, churn_count, cosine_distance_f32, percentile, run_bench,
};

// The flat `vector.rs` module used to provide these names to the inline test
// module through `use super::*`: the private helpers the tests name bare
// plus the private crate/std imports they rely on. After the directory split
// the seam re-imports them so `vector_tests.rs` resolves exactly as before.
#[cfg(test)]
use self::vector_run::{bench_config, gen_corpus, gen_queries, select_churn_ids};
#[cfg(test)]
use oneiron::EntityId;
#[cfg(test)]
use rand::{SeedableRng, rngs::StdRng};
#[cfg(test)]
use std::collections::BTreeMap;
