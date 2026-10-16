//! Header-only recovery of a retained soft-delete shell, never a body put.

use super::{
    BaseWriteOrigin, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader, apply_short_id_plan,
    plan_short_id_update, reject_overlay_member_base_write, stage_entity_index_rows,
};
use crate::error::{ArtifactError, Result};
use crate::{EntityId, Vault};

/// A canonical soft tombstone may retain a header and graph, but no payload.
/// Normal put validators require payloads and cannot represent this state.
/// This door restores only that deleted shape and reuses the normal index writer.
pub(crate) fn restore_recovery_shell_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    blob: &[u8],
    tombstone: &[u8],
) -> Result<()> {
    let invalid = || ArtifactError::InvalidRecoveryArtifact("retained soft shell");
    let header = EntityMetadataHeader::parse(blob).ok_or_else(invalid)?;
    if blob.len() != ENTITY_METADATA_HEADER_LEN
        || crate::deletion::decode_tombstone_value(tombstone).reason
            != Some(crate::deletion::TombstoneReason::UserDelete)
        || header.occurred_start > header.occurred_end
    {
        return Err(invalid().into());
    }
    // No maintenance, overlay or protected-id authority is supplied by a header.
    vault
        .store
        .validate_public_entity_type(header.entity_type)?;
    // An id that has been an agent stays one, on this door too (H215).
    crate::agent_def::refuse_agent_id_retype_in_txn(&vault.store, txn, id, header.entity_type)?;
    reject_overlay_member_base_write(&vault.store, id, BaseWriteOrigin::Ordinary)?;
    crate::claim::validate_claim_write_target_in_txn(&vault.store, txn, id, false)?;
    if vault.local_hard_delete_marker_exists_in_txn(txn, id)? {
        return Err(invalid().into());
    }
    if let Some(previous) = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
        && previous.get(..ENTITY_METADATA_HEADER_LEN) != Some(blob)
    {
        return Err(invalid().into());
    }
    // Scrub any admitted old body before installing the retained header. This
    // keeps D16, lexical, vector and domain cleanup on the ordinary delete door.
    vault.apply_replayed_tombstone_in_txn(txn, id, tombstone)?;
    let occurred = crate::temporal::TimeRange {
        start: header.occurred_start,
        end: header.occurred_end,
    };
    let short_id =
        if !crate::ports::ShortIdStoreMaintenance::port_short_id_mapping_exists(vault, txn, id)? {
            vault
                .store
                .short_id_prefix(header.entity_type)
                .ok()
                .map(|prefix| {
                    plan_short_id_update(&vault.store, txn, id, header.entity_type, &prefix, &[])
                })
                .transpose()?
        } else {
            None
        };
    crate::ports::EntityStoreMaintenance::port_retained_shell_restore(&vault.store, txn, id, blob)?;
    // A definition's shell keeps no body to bound its id by: it pins the id
    // at `Proposed` (on its seed's lineage, or with the lineage unread for
    // the next put to name) unless the id already answers to a pin, so
    // deleting the shell cannot reopen the id wider (H215).
    if header.entity_type == crate::registry::ENTITY_TYPE_AGENT_DEF {
        crate::agent_def::pin_stored_row_in_txn(&vault.store, txn, id)?;
    }
    stage_entity_index_rows(
        &vault.store,
        txn,
        id,
        header.entity_type,
        occurred,
        header.learned_at,
    )?;
    if let Some(plan) = short_id {
        apply_short_id_plan(&vault.store, txn, id, plan)?;
    }
    Ok(())
}
