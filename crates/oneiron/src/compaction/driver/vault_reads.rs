//! The driver's reads of the vault: the trigger-time durable watermark,
//! and whether a row is stored or tombstoned. Moved whole from `mod.rs`
//! (FIX 4933); the bodies are as they were.

use super::CompactionWatermark;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::vault::Vault;

/// Reads the trigger-time durable watermark through the Dreamer's existing
/// public surface (S-11, ONE-1793 v2).
///
/// The compound position is read whole: `last_learned_at` alone cannot
/// separate two turns sharing one second. `DreamerConsolidationScope::Micro`
/// names the Dreamer lane's OWN finest consolidation cursor — it is that
/// lane's enum variant, not a summary-tier name. Epoch summaries mint at the
/// unbounded integer `level` 0 and this module coins no tier vocabulary of
/// its own.
pub(super) fn snapshot_watermark(vault: &Vault) -> Result<CompactionWatermark> {
    let watermark = crate::dreamer_consolidation::read_watermark(
        vault,
        crate::store::consolidation_scope::DreamerConsolidationScope::Micro,
    )?;
    Ok(CompactionWatermark {
        learned_at: watermark.last_learned_at,
        turn_id: watermark.last_turn_id,
        turn: None,
    })
}

/// Whether the vault stores `id`, or stored it until a deletion whose
/// tombstone stands.
pub(super) fn stored_or_deleted_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    Ok(
        crate::ports::EntityStoreRead::port_entity_record(&vault.store, rtxn, id)?.is_some()
            || crate::ports::TombstoneStoreRead::port_deletion_state(&vault.store, rtxn, id)?
                .deleted,
    )
}
