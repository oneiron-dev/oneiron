//! Doors to the conversation membership index for tests/membership_index.rs (L6-16). Not API.

use std::collections::BTreeSet;

use crate::conversation::MembershipWindow;
use crate::conversation::membership_index_test_support as support;
use crate::{EntityId, Result, Vault};

/// Rows this thread's whole-ledger scans decoded. The count is cumulative;
/// the proof test measures the difference around index reads only.
pub fn ledger_rows_folded() -> u64 {
    support::ledger_rows_folded()
}

/// [`Vault::members_in_txn`] in one read transaction.
///
/// # Errors
///
/// The room's, as the reader reports it.
pub fn members(vault: &Vault, room: EntityId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    vault.members_in_txn(&txn, room)
}

/// [`Vault::members_in_record_order_in_txn`] in one read transaction.
///
/// # Errors
///
/// The room's, as the reader reports it.
pub fn members_in_record_order(vault: &Vault, room: EntityId) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    vault.members_in_record_order_in_txn(&txn, room)
}

/// [`Vault::is_member_in_txn`] in one read transaction.
///
/// # Errors
///
/// The room's, as the reader reports it.
pub fn is_member(vault: &Vault, room: EntityId, person: EntityId) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    vault.is_member_in_txn(&txn, room, person)
}

/// [`Vault::current_join_in_txn`] in one read transaction.
///
/// # Errors
///
/// The room's, as the reader reports it.
pub fn current_join(vault: &Vault, room: EntityId, person: EntityId) -> Result<Option<u64>> {
    let txn = vault.store.env.read_txn()?;
    vault.current_join_in_txn(&txn, room, person)
}

/// [`Vault::ever_members_in_txn`] in one read transaction.
///
/// # Errors
///
/// The room's, as the reader reports it.
pub fn ever_members(vault: &Vault, room: EntityId) -> Result<BTreeSet<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    vault.ever_members_in_txn(&txn, room)
}

/// [`Vault::membership_at_in_txn`] in one read transaction.
///
/// # Errors
///
/// The room's, as the reader reports it.
pub fn membership_at(vault: &Vault, room: EntityId, at: u64) -> Result<Vec<EntityId>> {
    let txn = vault.store.env.read_txn()?;
    vault.membership_at_in_txn(&txn, room, at)
}

/// [`Vault::windows_in_txn`] in one read transaction.
///
/// # Errors
///
/// The room's, as the reader reports it.
pub fn windows(vault: &Vault, room: EntityId, person: EntityId) -> Result<Vec<MembershipWindow>> {
    let txn = vault.store.env.read_txn()?;
    vault.windows_in_txn(&txn, room, person)
}

/// The ledger fold's members at `at`, in its own read transaction.
///
/// # Errors
///
/// The ledger's, as the fold reports it.
pub fn folded_members_at(vault: &Vault, room: EntityId, at: u64) -> Result<BTreeSet<EntityId>> {
    support::folded_members_at(vault, room, at)
}

/// The ledger fold's windows for `person`, in its own read transaction.
///
/// # Errors
///
/// The ledger's, as the fold reports it.
pub fn folded_windows(
    vault: &Vault,
    room: EntityId,
    person: EntityId,
) -> Result<Vec<MembershipWindow>> {
    support::folded_windows(vault, room, person)
}

/// The ledger fold's current-join index for `person`.
///
/// # Errors
///
/// The ledger's, as the fold reports it.
pub fn folded_current_join(vault: &Vault, room: EntityId, person: EntityId) -> Result<Option<u64>> {
    support::folded_current_join(vault, room, person)
}

/// The ledger fold's ever-joined set, in its own read transaction.
///
/// # Errors
///
/// The ledger's, as the fold reports it.
pub fn folded_ever_members(vault: &Vault, room: EntityId) -> Result<BTreeSet<EntityId>> {
    support::folded_ever_members(vault, room)
}

/// Drops `room`'s index rows, so its reads fold until its next change.
///
/// # Errors
///
/// The store's.
pub fn drop_room_index(vault: &Vault, room: EntityId) -> Result<()> {
    support::drop_room_index(vault, room)
}

/// Rebuilds the index for every room, as a restore does.
///
/// # Errors
///
/// The store's.
pub fn rebuild_index(vault: &Vault) -> Result<()> {
    support::rebuild_index(vault)
}

/// Plants `revision` as `room`'s ledger revision, past the append door.
///
/// # Errors
///
/// The store's.
pub fn set_ledger_revision(vault: &Vault, room: EntityId, revision: u64) -> Result<()> {
    support::set_ledger_revision(vault, room, revision)
}

/// A scoped audience read as `audience[0]`, over `room_rows`: installs a
/// `core:read` grant for the reader so the audience check runs, filters the
/// rows through `for_audience(audience)`, and returns `(kept, ledger_reads)`.
/// `audience` must not be empty; its first member is the reader, as the
/// tests read as the member they name.
///
/// # Errors
///
/// The store's, or the grant's.
pub fn audience_read(
    vault: &Vault,
    room_rows: &[EntityId],
    audience: &[EntityId],
) -> Result<(usize, usize)> {
    let reader = *audience
        .first()
        .ok_or(crate::error::Error::InvalidConfig("audience".into()))?;
    // Scoped reads are default-deny: without a `core:read` grant the policy
    // gate refuses each row before the audience check runs, so the kept count
    // would prove nothing. Install one for the reader on a second manifest,
    // as the quarantined conversation test does.
    let scope = crate::federation::scope_codec::encode_scope_value(
        &crate::federation::scope_codec::read_preset(),
    )?;
    let policy = rmpv::Value::Map(vec![
        ("schema_version".into(), "1.2".into()),
        ("pack_id".into(), "membership-index-test".into()),
        ("pack_version".into(), "1".into()),
        ("min_engine_version".into(), "0.0.0".into()),
        ("defaults".into(), rmpv::Value::Map(vec![])),
        ("rules".into(), rmpv::Value::Array(vec![])),
        ("actor_ceilings".into(), rmpv::Value::Array(vec![])),
        (
            "scoped_grants".into(),
            rmpv::Value::Array(vec![rmpv::Value::Map(vec![
                ("actor_ref".into(), reader.to_hex().into()),
                ("effector".into(), "core:read".into()),
                ("scope".into(), scope),
                ("receipt_required".into(), false.into()),
            ])]),
        ),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &policy)
        .map_err(|_| crate::error::Error::InvalidConfig("encode policy".into()))?;
    crate::test_fixtures::put_policy_manifest_bytes(vault, EntityId::now(), &bytes)?;
    let Some(key) = crate::claim::ScopedReadActorKey::new(reader.to_hex()) else {
        return Err(crate::error::Error::InvalidConfig("reader".into()));
    };
    let read = vault.scoped_read(key).for_audience(audience);
    let hits: Vec<crate::pipeline::ScoredEntity> = room_rows
        .iter()
        .map(|id| crate::pipeline::ScoredEntity {
            id: *id,
            score: 1.0,
        })
        .collect();
    let kept = read.filter_scored_entities(hits)?.len();
    Ok((kept, read.audience_ledger_reads()?))
}
