//! Doors for `tests/resume_preflight.rs` (L8-23): restamp the guest boundary a run's pending
//! step parked under, as an engine upgrade that adds a guest import would leave it; and give the
//! next step loop no attempt lease binds a root its runtime may cancel, as a hard queue control
//! cancels a leased loop's root (FIX 600).
//! Compiled only under `--cfg oneiron_test_support`; never API.

use std::cell::Cell;

use crate::engine_executor::ResumePreflightReport;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// Raises the owner's resume-divergence ask on `report`'s drift for `run`, as a held resume
/// raises it (L8-23).
pub fn raise_resume_divergence_ask(
    vault: &Vault,
    run: EntityId,
    report: &ResumePreflightReport,
) -> Result<()> {
    vault.with_write_txn_grouped(|wtxn| {
        crate::engine_executor::resume_divergence::raise_resume_divergence_ask_in_txn(
            vault, wtxn, run, report,
        )
    })
}

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

thread_local! {
    static CANCELLABLE_UNBOUND_ROOT: Cell<bool> = const { Cell::new(false) };
}

/// Arms one root: the next step loop on this thread that no attempt lease binds gets a root its
/// runtime may cancel, where it would get one nothing cancels.
pub fn cancellable_root_for_next_unbound_loop() {
    CANCELLABLE_UNBOUND_ROOT.with(|armed| armed.set(true));
}

/// Whether a cancellable root is armed on this thread; disarms it.
pub(crate) fn take_cancellable_unbound_root() -> bool {
    CANCELLABLE_UNBOUND_ROOT.with(Cell::take)
}
