//! Where a canonical code run's committed record stands, read outside its
//! entries (FIX 4606): its replay generation and the wait it is parked on
//! now. A host that readied an entry for one parked wait reads this again
//! once the run's single flight is the entry's own. A run that has left
//! that wait runs no batch for it. Nothing here enters the run.

use super::record::parked_wait_now;
use super::types::EngineExecutorResult;
use crate::code_run::{CodeRunReplayGeneration, ExecutorStorage, WaitKey};
use crate::{EntityId, Vault};

/// A canonical run's committed record as it stands now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeRunPosition {
    /// The record's replay generation.
    pub generation: CodeRunReplayGeneration,
    /// The key of the wait the run is parked on now, as its reply is
    /// delivered. `None` once the run resumed from its latest wait, or when
    /// it never parked.
    pub parked_wait: Option<WaitKey>,
}

/// Where canonical run `run_id`'s record stands now. `None` when the run
/// holds no replay record. The generation and the parked wait come from
/// one read of the record.
///
/// # Errors
///
/// Storage errors, a record whose generation does not count, and a terminal
/// marker that does not decode.
pub fn code_run_position(
    vault: &Vault,
    run_id: EntityId,
) -> EngineExecutorResult<Option<CodeRunPosition>> {
    let Some(record) = vault.get_code_run_replay_record(&run_id)? else {
        return Ok(None);
    };
    let parked_wait =
        parked_wait_now(&ExecutorStorage::Canonical(vault), &record)?.map(|(key, _)| key);
    Ok(Some(CodeRunPosition {
        generation: record.generation()?,
        parked_wait,
    }))
}
