//! BRST forward test oracle — ARCH-0052 off-record branch store (ONE-1725).
//!
//! Contract-level red tests for every subsequent phase of the branch-store
//! epic, authored with the P1 path opener (owner path-opener pattern). Each
//! test is `#[ignore = "armed by ONE-XXXX"]`: the arming ticket removes the
//! ignore, adapts SIGNATURES to the machinery it lands (the [`seam`] shims
//! below are the thinnest plausible surface, not a design), and NEVER weakens
//! an assertion. Assertions are count-exact by rule — never `any()`.
//!
//! Contract sources: ARCH-0052 §3 (D1–D9), §4 (test oracle), §7 (phase
//! plan); ticket acceptance criteria ONE-1726..ONE-1732; the wave-1 fence
//! findings ledger (reader-visibility breadth = the acceptance spec for the
//! base-leak sweep: `get_raw`-class raw reads first, then search/short-id,
//! edge readers, existence/enumeration, tree walks, ScopedRead, telemetry).

/// Thinnest plausible seam for machinery the arming tickets own.
///
/// Unarmed functions panic with the owning ticket. These signatures exist
/// ONLY so the oracle compiles red; each arming ticket replaces its shim with
/// the real API. Do NOT grow logic here.
mod seam;

mod tests_executor;
mod tests_leak_sweep;
mod tests_promote;
mod tests_substrate;
