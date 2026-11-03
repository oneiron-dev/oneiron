//! Per-id membership over the identity asks, hints and applied identity
//! inverses (FIX 10376): each row under every id its erase reads, so an
//! erase looks its rows up instead of scanning the table.
//!
//! Each table is `SideTable<(EntityId, PrimaryKeyBytes), (), Raw>`, after
//! `TAGGING_MENTION_REF`: one `sync_*_membership` helper per table moves a
//! row from its old id set to its new one in the caller's transaction, and
//! every primary `put`/`delete` site calls it with the before/after rows it
//! already holds. Membership is exactly the ids whose erase would change
//! the row: an ask's turn, message, candidates and provisional (never its
//! surfaced turn, which the erase never scrubs); a hint's named entity and
//! each contribution's turn and message; an inverse's ask copy, held
//! provisionals, settled entity and hint copies (never the source anchor,
//! the spans' links, the distinct assertions or the confirmed person).
//!
//! Each eraser looks its candidate rows up here, reads each one whole and
//! re-applies its existing pure predicate before mutating, so a stale
//! membership row costs an extra read, never a wrong scrub, and membership
//! holding every affected row means no missed scrub.

use std::collections::BTreeSet;

use super::super::applied::MaintenanceInverse;
use super::hints::{HintKey, StoredIdentityHint};
use super::{IdentityAsk, ProvisionalInverse, SettleInverse};
use crate::side_table::{self, Raw, SideKey, SideTable};
use crate::store::Store;
use crate::{EntityId, Result};

/// Each open ask under every id its erase reads (FIX 10376). Key: the id,
/// then the ask key.
pub(super) const ASK_BY_SOURCE: SideTable<(EntityId, [u8; 32]), (), Raw> =
    SideTable::new(&side_table::DREAMER_IDENTITY_ASK_BY_SOURCE);

/// Each saved hint under every id its erase reads (FIX 10376). Key: the id,
/// then the hint key.
pub(super) const HINT_BY_SOURCE: SideTable<(EntityId, HintKey), (), Raw> =
    SideTable::new(&side_table::DREAMER_IDENTITY_HINT_BY_SOURCE);

/// Each background identity disposition's inverse under every id its erase
/// reads (FIX 10376). Key: the id, then the ask key (the APPLIED IdentityAsk
/// target).
pub(in crate::dreamer_runner::maintenance) const INVERSE_BY_SOURCE: SideTable<
    (EntityId, [u8; 32]),
    (),
    Raw,
> = SideTable::new(&side_table::DREAMER_IDENTITY_INVERSE_BY_SOURCE);

/// Every id whose erase would change `ask` (FIX 10376): its turn, its
/// message, its candidates and its provisional entity. Its surfaced turn is
/// not one: the erase never scrubs it.
pub(super) fn ask_ids(ask: &IdentityAsk) -> BTreeSet<EntityId> {
    let mut ids = BTreeSet::from([ask.turn, ask.message]);
    ids.extend(ask.candidates.iter().copied());
    ids.extend(ask.provisional);
    ids
}

/// Every id whose erase would change the hint row `key` holds (FIX 10376):
/// the entity it named and each contribution's turn and message.
pub(super) fn hint_ids(key: &HintKey, stored: &StoredIdentityHint) -> BTreeSet<EntityId> {
    let mut ids = BTreeSet::from([key.2]);
    for each in &stored.sources {
        ids.insert(each.source.turn);
        ids.insert(each.source.message);
    }
    ids
}

/// Every id whose erase would change `inverse` (FIX 10376); a variant that
/// is never an identity inverse names none.
pub(in crate::dreamer_runner::maintenance) fn inverse_ids(
    inverse: &MaintenanceInverse,
) -> BTreeSet<EntityId> {
    match inverse {
        MaintenanceInverse::IdentitySettle(inverse) => inverse.named_ids(),
        MaintenanceInverse::IdentityProvisional(inverse) => inverse.named_ids(),
        _ => BTreeSet::new(),
    }
}

/// Moves one primary row's membership from `old` to `new` (FIX 10376):
/// drops the ids that left, adds the ones that joined, all in the caller's
/// transaction.
fn sync_sets<K: SideKey + Clone>(
    table: &SideTable<(EntityId, K), (), Raw>,
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &K,
    old: &BTreeSet<EntityId>,
    new: &BTreeSet<EntityId>,
) -> Result<()> {
    for id in old.difference(new) {
        table.delete(store, txn, &(*id, key.clone()))?;
    }
    for id in new.difference(old) {
        table.put(store, txn, &(*id, key.clone()), &())?;
    }
    Ok(())
}

/// Moves ask `key`'s membership from `old` to `new` (FIX 10376) in the
/// caller's transaction; none is no row.
pub(super) fn sync_ask_membership(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    old: Option<&IdentityAsk>,
    new: Option<&IdentityAsk>,
) -> Result<()> {
    sync_ask_sets(
        store,
        txn,
        key,
        &old.map(ask_ids).unwrap_or_default(),
        &new.map(ask_ids).unwrap_or_default(),
    )
}

/// [`sync_ask_membership`] over id sets the caller already holds (FIX
/// 10376): the erase path, which reads the old set before it scrubs.
pub(super) fn sync_ask_sets(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    old: &BTreeSet<EntityId>,
    new: &BTreeSet<EntityId>,
) -> Result<()> {
    sync_sets(&ASK_BY_SOURCE, store, txn, key, old, new)
}

/// Moves hint `key`'s membership from `old` to `new` (FIX 10376) in the
/// caller's transaction; none is no row.
pub(super) fn sync_hint_membership(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &HintKey,
    old: Option<&StoredIdentityHint>,
    new: Option<&StoredIdentityHint>,
) -> Result<()> {
    sync_hint_sets(
        store,
        txn,
        key,
        &old.map(|held| hint_ids(key, held)).unwrap_or_default(),
        &new.map(|held| hint_ids(key, held)).unwrap_or_default(),
    )
}

/// [`sync_hint_membership`] over id sets the caller already holds (FIX
/// 10376): the erase path, which reads the old set before it scrubs.
pub(super) fn sync_hint_sets(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &HintKey,
    old: &BTreeSet<EntityId>,
    new: &BTreeSet<EntityId>,
) -> Result<()> {
    sync_sets(&HINT_BY_SOURCE, store, txn, key, old, new)
}

/// Moves the inverse filed under ask `key`'s membership from `old` to `new`
/// (FIX 10376) in the caller's transaction; none is no row.
pub(in crate::dreamer_runner::maintenance) fn sync_inverse_membership(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    old: Option<&MaintenanceInverse>,
    new: Option<&MaintenanceInverse>,
) -> Result<()> {
    sync_inverse_sets(
        store,
        txn,
        key,
        &old.map(inverse_ids).unwrap_or_default(),
        &new.map(inverse_ids).unwrap_or_default(),
    )
}

/// [`sync_inverse_membership`] over id sets the caller already holds (FIX
/// 10376): the erase path, which reads the old set before it scrubs.
pub(in crate::dreamer_runner::maintenance) fn sync_inverse_sets(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    key: &[u8; 32],
    old: &BTreeSet<EntityId>,
    new: &BTreeSet<EntityId>,
) -> Result<()> {
    sync_sets(&INVERSE_BY_SOURCE, store, txn, key, old, new)
}
