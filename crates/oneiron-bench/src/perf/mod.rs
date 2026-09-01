//! `perf` subcommand — ONE-1579 performance bench harness.
//!
//! This is BEAM's SIBLING, not its successor. ONEIRON-ARCH-0042 keeps accuracy
//! and cost; this harness answers the separate question "does the engine hold
//! up". Its results live BESIDE the BEAM report and are never folded into a
//! BEAM score — there is no composite number anywhere in the output, and every
//! axis carries its own evidence kind, sample count and fail-closed cells.
//!
//! Commands:
//!
//! * `oneiron-bench perf run --plan <JSON> --out <JSON>` — run a plan and
//!   write the report.
//! * `oneiron-bench perf smoke` — run the bundled synthetic smoke. Always
//!   marked `synthetic_smoke` and explicitly non-publishable.
//! * `oneiron-bench perf wake-child ...` — harness-internal. Spawned BY the
//!   wake and ready-children probes as their ready child; not a user command.
//!
//! The eight axes, each reported separately:
//!
//! 1. Warm and cold recall/latency as two disjoint sample sets (never one
//!    average, never a merged percentile) — [`retrieval`], shaped by [`axes`].
//! 2. Wake latency measured by the parent's completed TCP `accept` — [`wake`].
//!    Log text is never read; children run with all standard streams discarded.
//! 3. The concurrent-session curve against ONE vault — [`sessions`]. A full run
//!    must walk exactly `[1, 10, 100, 300]`, and every worker is released from
//!    one gate so the point measures concurrency rather than thread creation.
//! 4. RSS across exactly ten ready child processes, each holding an open vault
//!    — [`resident_memory`]. The ARCH-0023b 50 MB per-vault budget rides along
//!    as a comparison slot.
//! 5. Gated-write SUCCESSFUL commits/s and error counts through
//!    `ClaimCandidate` + `WriteEnvelope` + `BatchBuilder::claim_candidate` /
//!    `commit`, with the gate ledger read back — [`gated_writes`].
//! 6. F32 / F16 / Int8Sq / `BinaryPrefixRescore` precision rows with their
//!    recall deltas against F32 — [`precision`]. BENCH representations only;
//!    the engine persist path stays f16.
//! 7. Real-traffic cache hit rates per listed rung, from bench-owned JSONL
//!    events — [`cache_events`]. `vault.rs` and `ppr.rs` retrieval internals
//!    are not instrumented.
//! 8. A descriptive NVMe sequential/random fsync row — [`nvme`]. Missing
//!    hardware stays explicitly missing.
//!
//! Beside the axes: [`provenance`] (where and from which exact inputs),
//! [`publication`] (every check the publish verdict rests on) and
//! [`acceptance`] (the ONE-1578 knobs and the ONE-1537 relationship).
//!
//! Fail-closed rules the code enforces rather than merely documents: a full run
//! below the >=1000-doc / >=100-query plan floor OR below >=100 COMPLETED
//! samples per set reports not-applicable latency cells instead of numbers; a
//! full run below >=1000 warmup / >=10000 measured gated writes is an invalid
//! plan; a `corpus.k` larger than the indexed corpus is an invalid plan; a
//! child hold that cannot outlast the accept-and-sample phase is an invalid
//! plan; a speedup is emitted only when BOTH sides were measured wall-clock in
//! the same run; a full run refuses any cache event that is not real traffic;
//! a listed cache rung with no admissible event is `not_ready`, never `0`; and
//! a full report is publishable only when every publication check passes.

pub(crate) mod acceptance;
pub(crate) mod axes;
pub(crate) mod binary16;
pub(crate) mod cache_events;
pub(crate) mod cells;
pub(crate) mod child_process;
pub(crate) mod cli;
pub(crate) mod corpus;
pub(crate) mod gated_writes;
pub(crate) mod nvme;
pub(crate) mod plan;
pub(crate) mod precision;
pub(crate) mod provenance;
pub(crate) mod publication;
pub(crate) mod report;
pub(crate) mod representations;
pub(crate) mod resident_memory;
pub(crate) mod retrieval;
pub(crate) mod runner;
pub(crate) mod sessions;
pub(crate) mod wake;

use std::process::ExitCode;

/// `perf` dispatch.
pub(crate) fn run(args: &[String]) -> ExitCode {
    cli::run(args)
}
