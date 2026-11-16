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
