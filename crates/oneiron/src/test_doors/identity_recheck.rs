//! The nightly identity re-check, one page, run from a test, and the open
//! identity asks after it (census item 12, the entity linker cascade).

use crate::dreamer_runner::maintenance::identity::IdentityAsk;
use crate::store::GateDecisionId;
use crate::{EntityId, Result, Vault};

/// Runs one page of the nightly identity re-check at `now` (seconds) and
/// returns every open identity ask.
pub fn run_identity_recheck(vault: &Vault, now: u64) -> Result<Vec<IdentityAsk>> {
    crate::dreamer_runner::maintenance::identity::recheck_page_for_test(vault, now)
}

/// Opens `claim`'s owner-answer obligation (ARCH-0026 §G3), as a replica's
/// revision of a held critical claim leaves it: the claim keeps its stored
/// approval, and every effect reader holds it until its owner answers.
pub fn open_owner_answer_obligation(vault: &Vault, claim: &EntityId) -> Result<()> {
    vault.with_write_txn(|wtxn| {
        vault
            .store
            .open_owner_answer_obligation_in_txn(wtxn, claim, GateDecisionId::now(), &[])
    })
}
