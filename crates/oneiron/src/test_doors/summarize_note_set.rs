//! Doors for `tests/summarize_note_set.rs` (VAULT-SUMMARIZE-SET): the run's
//! answer read back from a later step's observation.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// The run's answer at step `step`: that step's observation text as its
/// replay record holds it, which is what `execute_code` releases to its
/// caller. Reads the committed record from the vault, never the run's own
/// response. Step 0 is what [`crate::test_doors::code_run_answer::finish_text`]
/// reads; a run that parked and resumed finishes on a later step, whose
/// answer only this read reaches.
///
/// # Errors
///
/// A missing replay record or observation, or the store's.
pub fn observation_text(vault: &Vault, run_id: &EntityId, step: u64) -> Result<String> {
    let record = vault
        .get_code_run_replay_record(run_id)?
        .ok_or(Error::CorruptedIndex("the run has no replay record"))?;
    let path = crate::engine_executor::observation_output_path(step);
    let output = record
        .outputs
        .iter()
        .find(|output| output.path == path)
        .ok_or(Error::CorruptedIndex(
            "the run has no such step observation",
        ))?;
    let storage = crate::code_run::ExecutorStorage::Canonical(vault);
    let raw = storage
        .get_code_run_raw_output(output)?
        .ok_or(Error::CorruptedIndex(
            "the run has no such step observation bytes",
        ))?;
    String::from_utf8(raw)
        .map_err(|_| Error::InvalidClaimBody("executor replay output is not utf8"))
}
