//! Owner restore of archived agent power grants (SIDE-2a).
//!
//! Each archived `AGENT_DEF_POWER_GRANT` row lands only when its holder still
//! exists on this vault's canonical route: a live `AGENT_DEF` for tag 0, an
//! extant attempt record for tag 1, an extant canonical reader job for tag 2.
//! The landing never manufactures a holder and never narrows a live grant by
//! fieldwise meet; a different stored byte stays live.

use super::powers::{
    AgentPowerTarget, POWER_GRANTS, decode_power_grant_row, decode_power_grant_target,
};
use crate::Vault;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::code_run::ReaderJob;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::side_table::{Raw, SideTable};
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Canonical reader-job rows, read in the import transaction for tag-2 holder checks.
const READER_JOBS: SideTable<EntityId, ReaderJob, Raw> =
    SideTable::new(&crate::side_table::CODE_RUN_READER_JOB);

/// Lands archived power grants whose holders exist, holding back the rest.
pub(crate) fn land_archived_agent_def_rows_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    for row in rows {
        let outcome = match decode_archived_row(&POWER_GRANTS, row) {
            Err(reason) => ArchivedSideRowOutcome::HeldBack(reason),
            Ok((key, value)) => match holder_holdback_in_txn(vault, &*txn, &key, &value)? {
                Some(reason) => ArchivedSideRowOutcome::HeldBack(reason),
                None => install_archived_row(&POWER_GRANTS, vault, txn, permit, &key, row)?,
            },
        };
        outcomes.push(outcome);
    }
    Ok(outcomes)
}

/// The holdback reason for one decoded grant row, or `None` when its holder exists.
fn holder_holdback_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    key: &[u8; 17],
    value: &[u8; 1],
) -> Result<Option<RetainedSideHeldBackReason>> {
    use RetainedSideHeldBackReason::{
        InvalidEncoding, InvalidValue, MissingLiveEntity, WrongEntityKind,
    };
    if decode_power_grant_row(*value).is_err() {
        return Ok(Some(InvalidValue));
    }
    let Some(target) = decode_power_grant_target(key) else {
        return Ok(Some(InvalidEncoding));
    };
    match target {
        AgentPowerTarget::Agent(id) => match live_entity_row_in_txn(&vault.store, txn, &id)? {
            LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_AGENT_DEF => {
                Ok(None)
            }
            LiveEntityRow::Live { .. } => Ok(Some(WrongEntityKind)),
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => Ok(Some(MissingLiveEntity)),
        },
        AgentPowerTarget::Attempt(id) => {
            if vault
                .store
                .attempt_records
                .get(txn, id.as_bytes())?
                .is_some()
            {
                Ok(None)
            } else {
                Ok(Some(MissingLiveEntity))
            }
        }
        AgentPowerTarget::ReaderTask(task) => {
            if READER_JOBS.contains(&vault.store, txn, &task)? {
                Ok(None)
            } else {
                Ok(Some(MissingLiveEntity))
            }
        }
    }
}
