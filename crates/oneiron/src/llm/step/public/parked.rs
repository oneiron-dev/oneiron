//! The owner's model steps parked on their offer's health, for the host that
//! resumes them after a restart (STEP-PARK-BOOT-RESUME). A step parked on a
//! server resumes from that server's own task; a restart drops the task, and
//! the row is all that is left of it.

use super::{
    AttemptId, AuthenticatedOwner, Error, MemoryResult, ModelStepResult, ModelStepSubmit,
    SUBMISSIONS, Vault, identity,
};
use crate::side_table::SideKey;

/// One of the owner's parked steps: the input the owner submitted, and when
/// its offer is back, as Unix seconds on the vault's clock (none while a
/// probation request is out).
#[derive(Debug, Clone)]
pub struct ParkedStep {
    pub input: ModelStepSubmit,
    pub until: Option<u64>,
}

/// The owner's own steps that rest parked (FIX 11226), read in one snapshot
/// under the owner's live proof. Each is listed as the owner submitted it,
/// so a submission of its input resumes the very row, with the sends and
/// the correction point it keeps. A live run's parked step is not listed:
/// its lease admits it, not an owner proof, and the run's next submission
/// of its key resumes it. Neither is another person's.
///
/// # Errors
///
/// The owner's proof no longer holds, or a storage error.
pub fn parked_as_owner(vault: &Vault, owner: &AuthenticatedOwner) -> MemoryResult<Vec<ParkedStep>> {
    let txn = vault.store.env.read_txn().map_err(Error::from)?;
    let actor = owner.revalidate_in_txn(vault, &txn)?;
    let needle = actor.to_hex();
    let mut parked = Vec::new();
    for row in SUBMISSIONS.iter_raw_from(&vault.store, &txn, &[])? {
        let (key, bytes) = row?;
        // The actor's id rests in its row as its hex text: a row without
        // the owner's (a run's step) is not decoded.
        if !bytes
            .windows(needle.len())
            .any(|window| window == needle.as_bytes())
        {
            continue;
        }
        // A row that does not decode is no step anyone can resume.
        let Ok(row) = SUBMISSIONS.decode_value(&bytes) else {
            continue;
        };
        let Some(ModelStepResult::Parked { until, .. }) = &row.result else {
            continue;
        };
        let until = *until;
        if row.actor != actor {
            continue;
        }
        // The owner's step under this key is this row: a submission of
        // the input reaches it.
        let Some(id) = <AttemptId as SideKey>::decode_key(&key) else {
            continue;
        };
        if id != identity(actor, &row.input.step_key)? {
            continue;
        }
        parked.push(ParkedStep {
            input: row.input,
            until,
        });
    }
    Ok(parked)
}
