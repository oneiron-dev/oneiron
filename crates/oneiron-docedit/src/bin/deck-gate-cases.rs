//! `deck-gate-cases`: the engine half of the OF-510 deck gate runner.
//!
//! It generates the `pptx-live-v1` candidates through the current projector
//! and runs every engine step of the eight-step check, writing the
//! candidates, their SHA-256 pins, the checks PowerPoint owes each one and
//! the run manifest to a new directory. Each case is journaled in that
//! directory's `results.jsonl` as it finishes, with one progress line on
//! stderr, so a run cut short keeps every case it finished. The Office half
//! (`office/deck_gate.py` inside that directory) runs on the Mac mini and
//! assembles the oracle receipt. docs/ops/deck-gate.md has the commands.
//!
//! This binary has no Loro body, so step 4's two-peer convergence case
//! stays inconclusive here; the gate's engine half runs the engine's
//! `deck-gate-engine` (crates/oneiron), the same runner with that merge.
//! `--source` names the commit the runner was built from; without it the
//! run's provenance is recorded as missing and step 6 stays inconclusive.
//!
//! Exit status: 0 when every engine half passed, 1 when the run was written
//! but an engine half failed or stayed open, 2 when no complete run was
//! written (the journal keeps whatever cases finished).

use std::process::ExitCode;

fn main() -> ExitCode {
    oneiron_docedit::live::oracle_run::main_with("deck-gate-cases", std::env::args().skip(1), None)
}
