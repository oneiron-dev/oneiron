//! Doors for `tests/audit_read_removal.rs` (Astra delta auditread-8435-pr1-delta
//! D1 and D2): the removals that reach an audit_read grant past a delete
//! door's header read. A peer's replayed tombstone and a carried Shell cutoff,
//! as the sync receiver applies them, and the headerless delete leg a delete
//! takes when its header read found no row.

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;

/// Replays a peer's tombstone for `id` here, as the sync receiver applies
/// one: a `user_delete` (soft) or, with `hard`, a `user_hard_delete` one.
///
/// # Errors
/// The replay's refusal, or the store's.
#[cfg(feature = "sync")]
pub fn replay_peer_tombstone(vault: &Vault, id: &EntityId, hard: bool) -> Result<()> {
    let reason = if hard {
        crate::deletion::TombstoneReason::UserHardDelete
    } else {
        crate::deletion::TombstoneReason::UserDelete
    };
    let value = crate::deletion::TombstoneValueV2 {
        reason,
        deleted_at: vault.store.clock.now_recorded_at(),
        request_id: vault.store.clock.ulid()?,
    }
    .encode();
    vault
        .apply_replayed_tombstone_for_sync(id, &value)
        .map(|_| ())
}

/// Applies a Shell cutoff another machine of this vault carries for `id`,
/// covering every generation, as the sync receiver applies one to a resident
/// row. Whether it withdrew the row.
///
/// # Errors
/// The store's.
#[cfg(feature = "sync")]
pub fn withdraw_on_received_shell_cutoff(vault: &Vault, id: &EntityId) -> Result<bool> {
    let mut wtxn = vault.store.env.write_txn()?;
    let withdrew = crate::deletion::withdraw_received_record_in_txn(
        &crate::secret_custody::CustodyWrite::of(vault),
        &mut wtxn,
        id,
        u64::MAX,
    )?;
    wtxn.commit()?;
    Ok(withdrew)
}

/// Deletes `id` (purged with `purge`) through the headerless leg, as a delete
/// takes it when its header read found no row: a row the owner wrote after
/// that read is what the leg then finds.
///
/// # Errors
/// The delete's refusal, or the store's.
pub fn delete_past_the_header_read(vault: &Vault, id: &EntityId, purge: bool) -> Result<()> {
    let reason = if purge {
        crate::deletion::DeleteReason::UserHardDelete
    } else {
        crate::deletion::DeleteReason::UserDelete
    };
    vault
        .delete_entity_without_header_read_for_test(id, reason)
        .map(|_| ())
}
