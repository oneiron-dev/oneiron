//! Doors for `tests/audit_read_removal.rs` (Astra delta auditread-8435-pr1-delta
//! D1 and D2, delta-2 F1 and F4): the removals that reach an audit_read grant
//! past a delete door's header read. A peer's replayed tombstone and a carried
//! Shell cutoff, as the sync receiver applies them, and how it settles the
//! replay's refusal; the headerless delete leg a delete takes when its header
//! read found no row, and that leg's tombstone publication past its scope
//! probe.

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

/// Publishes a purge's tombstone for `id` as the headerless delete leg does
/// once its scope probe passed: a grant the owner wrote after that probe is
/// what the publication then finds (Astra delta-2 F1). The purge that would
/// follow is left out: the publication alone commits the deletion fence.
///
/// # Errors
/// The publication's refusal, or the store's.
#[cfg(feature = "sync")]
pub fn publish_purge_past_the_scope_probe(vault: &Vault, id: &EntityId) -> Result<()> {
    vault.publish_purge_tombstone_for_test(id).map(drop)
}

/// Whether the sync receiver takes the refusal a peer's tombstone for `id`
/// meets here as that peer's rejected op, which it quarantines and goes on
/// past, rather than as a local failure it marks for retry: the classifier
/// the tombstone bridge and the forward rematerialization pass both ask
/// (Astra delta-2 F4). `None` when the replay is not refused.
#[cfg(feature = "sync")]
pub fn peer_tombstone_refusal_is_quarantined(
    vault: &Vault,
    id: &EntityId,
    hard: bool,
) -> Option<bool> {
    replay_peer_tombstone(vault, id, hard)
        .err()
        .map(|refusal| crate::sync::quarantine::remote_rejection_reason(&refusal).is_some())
}
