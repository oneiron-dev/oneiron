//! Owner restore of archived widen proposals (SIDE-4b G3).
//!
//! This worker lives beside the private widen table so it reuses the writer's own row
//! validation. Unresolved rows land only while unexpired with a live agent proposer;
//! resolved rows install as inert history. No landing mints a grant, retires a predecessor,
//! writes a receipt, or rebuilds the contact-verdict index; live scans cover an unindexed
//! install.

use super::WIDEN_PROPOSALS;
use super::rows::validate_row_fields;
use crate::Vault;
use crate::batch::export::archive_side_install::{
    ArchivedSideRowOutcome, decode_archived_row, install_archived_row,
};
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::error::Result;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};

/// Lands one archived widen row after the writer's field checks and, while unresolved, its
/// expiry and proposer checks.
pub(crate) fn land_archived_widen_row_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    row: &ArchiveRetainedSideRow,
) -> Result<ArchivedSideRowOutcome> {
    use RetainedSideHeldBackReason::{
        InvalidEncoding, InvalidValue, MissingLiveEntity, WrongEntityKind,
    };
    let (key, value) = match decode_archived_row(&WIDEN_PROPOSALS, row) {
        Err(reason) => return Ok(ArchivedSideRowOutcome::HeldBack(reason)),
        Ok(decoded) => decoded,
    };
    if validate_row_fields(&value, &key).is_err() {
        return Ok(ArchivedSideRowOutcome::HeldBack(InvalidEncoding));
    }
    if !value.resolved {
        if value.proposal.expires_at <= vault.store.clock.now_recorded_at() {
            return Ok(ArchivedSideRowOutcome::HeldBack(InvalidValue));
        }
        let proposer = match crate::EntityId::from_hex(&value.proposal.proposer) {
            Ok(id) => id,
            // Unreachable after `validate_row_fields`, held back fail-closed.
            Err(_) => return Ok(ArchivedSideRowOutcome::HeldBack(InvalidEncoding)),
        };
        match live_entity_row_in_txn(&vault.store, &*txn, &proposer)? {
            LiveEntityRow::Live { entity_type, .. } => {
                if crate::provenance::validate_actor_class(
                    entity_type,
                    crate::EdgeActorClass::Agent,
                )
                .is_err()
                {
                    return Ok(ArchivedSideRowOutcome::HeldBack(WrongEntityKind));
                }
            }
            LiveEntityRow::Absent | LiveEntityRow::DeletedShell => {
                return Ok(ArchivedSideRowOutcome::HeldBack(MissingLiveEntity));
            }
        }
    }
    install_archived_row(&WIDEN_PROPOSALS, vault, txn, permit, &key, row)
}
