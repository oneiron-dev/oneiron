//! The entity a vault-wide knob's fit is learned on (FIX 8079): an
//! engine-owned ASSET at the knob's [`super::global_setting_subject`], so the
//! learning projection has a row to write its claim about.

use serde_json::json;

use crate::Vault;
use crate::entity_id::EntityId;
use crate::ports::TombstoneStoreRead;
use crate::registry::ENTITY_TYPE_ASSET;
use crate::temporal::TimeRange;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// The plain label a vault-wide knob's subject ASSET carries, beside the
/// knob's key.
const GLOBAL_SETTING_SUBJECT_LABEL: &str = "learning setting (vault-wide)";

/// Why a vault-wide knob's subject is not ready, so a check on it is passed
/// over and the write that carries it goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SubjectUnready {
    /// The subject's row was erased; an erase is never undone here.
    Erased,
    /// A row of another kind holds the subject's id.
    Occupied,
    /// Reading or writing the subject failed.
    Unwritten,
}

/// Ensures `subject`, the global subject of `key`, is a live ASSET in `wtxn`
/// before a check on it projects: written once, in a savepoint so a failure
/// leaves `wtxn` as it was. Every device writes the same row, with fixed
/// stamps, as the bootstrap skills are.
pub(super) fn ensure_global_setting_subject_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    key: &str,
    subject: &EntityId,
) -> std::result::Result<(), SubjectUnready> {
    let mut savepoint = vault.store.env.nested_write_txn(wtxn).map_err(unwritten)?;
    match live_entity_row_in_txn(&vault.store, &savepoint, subject).map_err(unwritten)? {
        LiveEntityRow::Live { entity_type, .. } if entity_type == ENTITY_TYPE_ASSET => {
            return Ok(());
        }
        LiveEntityRow::Live { .. } => return Err(SubjectUnready::Occupied),
        LiveEntityRow::DeletedShell => return Err(SubjectUnready::Erased),
        LiveEntityRow::Absent => {}
    }
    let deletion = vault
        .store
        .port_deletion_state(&savepoint, subject)
        .map_err(unwritten)?;
    if deletion.deleted || deletion.stale {
        return Err(SubjectUnready::Erased);
    }
    let body = serde_json::to_vec(&json!({
        "label": GLOBAL_SETTING_SUBJECT_LABEL,
        "setting": key,
    }))
    .map_err(unwritten)?;
    vault
        .batch_in()
        .put(
            subject,
            ENTITY_TYPE_ASSET,
            TimeRange { start: 0, end: 0 },
            0,
            &body,
        )
        .apply(&mut savepoint)
        .map_err(unwritten)?;
    savepoint.commit().map_err(unwritten)
}

/// A read or write that failed, as [`SubjectUnready::Unwritten`].
fn unwritten<E>(_: E) -> SubjectUnready {
    SubjectUnready::Unwritten
}
