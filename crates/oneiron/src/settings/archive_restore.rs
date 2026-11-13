//! The owner's archive restore over the settings tables: each envelope lands through its owning
//! check, or stays retained.

use super::backup::land_archived_backup_policy_row_in_txn;
use super::board_layout::land_archived_board_layout_row_in_txn;
use super::non_base_world_claim_fraction::land_archived_non_base_world_claim_fraction_row_in_txn;
use super::room_threads::land_archived_room_threads_admin_delete_row_in_txn;
use super::room_threads::land_archived_room_threads_admin_walk_in_row_in_txn;
use super::snapshot_read::land_archived_snapshot_read_row_in_txn;
use super::undo_send::land_archived_undo_send_row_in_txn;
use super::{
    land_archived_customization_event_row_in_txn, land_archived_customization_settings_row_in_txn,
    land_archived_plugin_suggestions_row_in_txn, repair_customization_event_counter_in_txn,
};
use crate::Vault;
use crate::batch::export::archive_side_install::ArchivedSideRowOutcome;
use crate::batch::export::{
    ArchiveRetainedSideRow, OwnerArchiveRestorePermit, RetainedSideHeldBackReason,
};
use crate::error::Result;
use crate::side_table;

/// Lands the owner's archived settings envelopes in input order, repairing the customization event
/// counter when an event key is live.
pub(crate) fn land_archived_settings_rows_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    permit: &OwnerArchiveRestorePermit,
    rows: &[ArchiveRetainedSideRow],
) -> Result<Vec<ArchivedSideRowOutcome>> {
    let mut outcomes = Vec::with_capacity(rows.len());
    let mut event_key_live = false;
    for row in rows {
        let outcome = match row.source_table.as_str() {
            name if name == side_table::BACKUP_POLICY.name => {
                land_archived_backup_policy_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::BOARD_LAYOUT_SETTINGS.name => {
                land_archived_board_layout_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::CUSTOMIZATION_EVENT.name => {
                land_archived_customization_event_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::CUSTOMIZATION_SETTINGS.name => {
                land_archived_customization_settings_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::NON_BASE_WORLD_CLAIM_FRACTION.name => {
                land_archived_non_base_world_claim_fraction_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::PLUGIN_SUGGESTIONS_ENABLED.name => {
                land_archived_plugin_suggestions_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::ROOM_THREADS_ADMIN_DELETE.name => {
                land_archived_room_threads_admin_delete_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::ROOM_THREADS_ADMIN_WALK_IN.name => {
                land_archived_room_threads_admin_walk_in_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::SNAPSHOT_READ_SETTINGS.name => {
                land_archived_snapshot_read_row_in_txn(vault, txn, permit, row)?
            }
            name if name == side_table::UNDO_SEND_SETTING.name => {
                land_archived_undo_send_row_in_txn(vault, txn, permit, row)?
            }
            // The dispatcher never sends a foreign envelope here; without an
            // owning table the envelope has no decoding.
            _ => ArchivedSideRowOutcome::HeldBack(RetainedSideHeldBackReason::InvalidEncoding),
        };
        if row.source_table == side_table::CUSTOMIZATION_EVENT.name
            && matches!(
                outcome,
                ArchivedSideRowOutcome::Installed
                    | ArchivedSideRowOutcome::Unchanged
                    | ArchivedSideRowOutcome::KeptLive
            )
        {
            event_key_live = true;
        }
        outcomes.push(outcome);
    }
    if event_key_live {
        repair_customization_event_counter_in_txn(vault, txn)?;
    }
    Ok(outcomes)
}
