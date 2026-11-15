//! Doors for `tests/audit_read_removal.rs` (Astra delta auditread-8435-pr1-delta
//! D1 and D2, delta-2 F1 and F4): the removals that reach an audit_read grant
//! past a delete door's header read. A peer's replayed tombstone and a carried
//! Shell cutoff, as the sync receiver applies them, and how it settles the
//! replay's refusal; the headerless delete leg a delete takes when its header
//! read found no row, and that leg's tombstone publication past its scope
//! probe. The settlement of a privacy erase a hold refused before any grant
//! check ran (Astra delta-4 F3), and whether it left a use limit. The
//! restriction step of the owner's answer to a courtesy ask, past a coverage
//! check a forged delivery-ledger row passes (Astra delta-5 J2).

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

/// The last step of a privacy erase that raced the owner's grant and his hold
/// past its first grant check (Astra delta-4 F3): the hold check refuses
/// `id` as a privacy erase, and the delete facade settles that refusal in
/// its own write. Returns the hold check's answer.
///
/// # Errors
/// The hold check's refusal, or the store's.
pub fn settle_a_privacy_erase_refusal(vault: &Vault, id: &EntityId) -> Result<()> {
    let refusal = {
        let txn = vault.store.env.read_txn()?;
        let actor = crate::store::legal_hold::HoldActor::UNATTRIBUTED.privacy(true);
        vault.store.reject_legal_holds_in_txn(&txn, &[*id], &actor)
    };
    vault.store.flush_legal_hold_refusals_settled();
    refusal
}

/// Whether a refused privacy erase keeps `id` under a use limit that a
/// standing hold backs: the limit hides the record from safe reads.
///
/// # Errors
/// The store's.
pub fn use_limited(vault: &Vault, id: &EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    Ok(crate::store::legal_hold::legal_hold_use_limit_in_txn(&vault.store, &txn, id)?.is_some())
}

/// Restricts `id` pending review as the owner's (`owner`) answer to a
/// courtesy ask does once its coverage check passed `id` as a present copy
/// the pact delivered (Astra delta-5 J2): a delivery-ledger row the generic
/// sync-state writer that writes only absent rows planted passes that check.
/// The restriction hides `id` from safe reads.
///
/// # Errors
/// The restriction's refusal, or the store's.
pub fn restrict_as_a_cooperative_answer(
    vault: &Vault,
    id: &EntityId,
    owner: EntityId,
) -> Result<()> {
    let now = vault.store.clock.now_recorded_at();
    vault.restrict_as_a_cooperative_answer_for_test(*id, owner, now)
}
