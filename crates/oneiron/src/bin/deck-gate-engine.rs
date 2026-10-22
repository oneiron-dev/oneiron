//! `deck-gate-engine`: the OF-510 deck gate's engine half with the engine's
//! own Loro body. It is docedit's `deck-gate-cases` runner, handed the
//! engine's two-peer merge of one deck body (`office_body::merge_deck_peers`),
//! so step 4's convergence case merges real Loro peers in both import
//! orders. `scripts/office/deck_gate_linux.sh` runs it; docs/ops/deck-gate.md
//! has the commands and the exit statuses.

use std::process::ExitCode;

fn main() -> ExitCode {
    oneiron_docedit::live::oracle_run::main_with(
        "deck-gate-engine",
        std::env::args().skip(1),
        Some(oneiron::office_body::merge_deck_peers),
    )
}
