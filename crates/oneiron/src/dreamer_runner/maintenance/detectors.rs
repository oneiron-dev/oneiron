//! The Coach's nightly detector pass (ARCH-0066 §4, OF-298): the tier-1
//! sweep over Gate receipts plus the served-signal detectors, then the
//! degenerate-output door fed by the served conversation turns. One
//! unexplained empty turn files a silent-conversation diagnostic, which
//! stays a diagnostic: no closed-form repair answers it. The Dreamer's
//! own output facts have no durable served row yet, so the degenerate
//! detector keeps its caller-fed door until one lands (OF-418).
use crate::self_heal::TIER1_SWEEP_SCOPE;
use crate::self_heal::tripwires::DreamerRunFacts;
use crate::{Result, Vault};

/// Retrieval runs one pass reads for conversation facts, newest first.
const CONVERSATION_RUNS: usize = 1_024;

/// The nightly tier-1 detection, as the Coach.
pub(super) fn run(vault: &Vault, now: u64) -> Result<()> {
    vault.run_tier1_sweep(now)?;
    let runs = vault.retrieval_runs(CONVERSATION_RUNS)?;
    let facts: Vec<DreamerRunFacts> = runs
        .iter()
        .filter_map(DreamerRunFacts::from_retrieval_turn)
        .collect();
    let diagnostics = vault.run_dreamer_output_tripwires(TIER1_SWEEP_SCOPE, &facts)?;
    vault.propose_tier1_repairs(&diagnostics, now)?;
    Ok(())
}
