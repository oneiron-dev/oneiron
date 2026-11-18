//! Doors for `tests/resume_preflight.rs` (L8-23): restamp the guest boundary a run's pending
//! step parked under, as an engine upgrade that adds a guest import would leave it.
//! Compiled only under `--cfg oneiron_test_support`; never API.

use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// Reads the run's replay record, sets its pending step's `guest_abi`, and puts it back under
/// its generation (L8-23). It fails if the run holds no record or no pending step.
pub fn restamp_guest_abi(vault: &Vault, run: EntityId, guest_abi: [u8; 32]) -> Result<()> {
    let mut record = vault
        .get_code_run_replay_record(&run)?
        .ok_or(Error::EntityNotFound)?;
    let expected = Some(record.generation()?);
    let Some(pending) = record.pending_step.as_mut() else {
        return Err(Error::InvalidConfig(
            "the run holds no pending step".to_owned(),
        ));
    };
    pending.guest_abi = guest_abi;
    vault
        .put_code_run_replay_record_if_generation(&record, expected)
        .map(|_| ())
}
