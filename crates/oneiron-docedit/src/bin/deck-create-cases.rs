//! `deck-create-cases`: the engine half of the `deck-create-v1` oracle runner.
//!
//! It replays the pinned `deck-create-v1` case set through the current emitter, writing each case's
//! candidate bytes, the fit-unverified units PowerPoint owes each one and the run manifest to a new
//! directory. A case whose brief does not compile becomes a `refused` row; the run goes on. The Office
//! half (`office/deck_create_gate.py` inside that directory) runs on the Mac mini and measures every
//! unit in PowerPoint. docs/ops/deck-gate.md has the commands.
//!
//! `--source` names the commit the runner was built from; without it the run's provenance is recorded
//! as empty, and the receipt pins that.
//!
//! Exit status: 0 when every case has a candidate, 1 when some case was refused, 2 when no manifest
//! was written (bad arguments, an existing `--out`, an unreadable case manifest).

use std::process::ExitCode;

fn main() -> ExitCode {
    oneiron_docedit::emit::oracle_cases::main_with("deck-create-cases", std::env::args().skip(1))
}
