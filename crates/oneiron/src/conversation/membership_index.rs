//! Per-participant membership index (ARCH-0052 :215, ASTRA-1406b).
//! A roster check folded the whole ledger, two or more times per call. Each
//! person row now holds that person's fold. A room is complete only when its
//! indexed revision equals its nonzero ledger revision; any doubt falls back
//! to the ledger. An old room folds until its next membership change, and a
//! restore rebuilds the index (zero migration, ARCH-0052 D9).

use super::membership::{
    MEMBERSHIP_SEQ, MembershipAction, MembershipRow, MembershipWindow, apply_window_row, rows_in,
};
use crate::side_table::{self, Named, Raw, SideTable};
use crate::store::Store;
use crate::{EntityId, Result, Vault};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// One person's membership fold, in ledger order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct PersonMembership {
    /// All windows opened by this person's Join rows, in ledger order.
    pub(super) windows: Vec<MembershipWindow>,
    /// Ledger index of the Join that opened the current membership, if any.
    pub(super) current_join: Option<u64>,
}

const PERSON_MEMBERSHIP: SideTable<(EntityId, EntityId), PersonMembership, Named> =
    SideTable::new(&side_table::CONVERSATION_MEMBERSHIP_PERSON);
const INDEXED_REVISION: SideTable<EntityId, u64, Raw> =
    SideTable::new(&side_table::CONVERSATION_MEMBERSHIP_INDEXED);

pub(super) fn indexed_revision_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<u64>> {
    let revision = MEMBERSHIP_SEQ.get(store, txn, &room)?;
    let Ok(indexed) = INDEXED_REVISION.get(store, txn, &room) else {
        return Ok(None);
    };
    Ok(match (revision, indexed) {
        (Some(revision), Some(indexed)) if revision > 0 && revision == indexed => Some(revision),
        _ => None,
    })
}

pub(super) fn person_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
    person: EntityId,
) -> Result<Option<PersonMembership>> {
    if indexed_revision_in(store, txn, room)?.is_none() {
        return Ok(None);
    }
    Ok(PERSON_MEMBERSHIP
        .get(store, txn, &(room, person))
        .ok()
        .map(Option::unwrap_or_default))
}

pub(super) fn entries_in(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    room: EntityId,
) -> Result<Option<Vec<(EntityId, PersonMembership)>>> {
    if indexed_revision_in(store, txn, room)?.is_none() {
        return Ok(None);
    }
    Ok(PERSON_MEMBERSHIP
        .scan_from(store, txn, room.as_bytes())
        .ok()
        .map(|entries| {
            entries
                .into_iter()
                .map(|((_, person), entry)| (person, entry))
                .collect()
        }))
}

pub(super) fn record_in(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    index: u64,
    row: &MembershipRow,
) -> Result<()> {
    let mut entry = match PERSON_MEMBERSHIP.get(store, txn, &(room, row.person)) {
        Ok(entry) => entry.unwrap_or_default(),
        Err(_) => return drop_room_in(store, txn, room),
    };
    if apply_window_row(&mut entry.windows, row).is_err() {
        return drop_room_in(store, txn, room);
    }
    match row.action {
        MembershipAction::Join => entry.current_join = Some(index),
        MembershipAction::Leave => entry.current_join = None,
        MembershipAction::History => {}
    }
    PERSON_MEMBERSHIP.put(store, txn, &(room, row.person), &entry)?;
    INDEXED_REVISION.put(store, txn, &room, &(index + 1))
}

pub(super) fn rebuild_room_in(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    room: EntityId,
    rows: &[MembershipRow],
) -> Result<()> {
    drop_room_in(store, txn, room)?;
    let mut entries: BTreeMap<EntityId, PersonMembership> = BTreeMap::new();
    for (index, row) in (0_u64..).zip(rows) {
        let entry = entries.entry(row.person).or_default();
        if apply_window_row(&mut entry.windows, row).is_err() {
            return Ok(());
        }
        match row.action {
            MembershipAction::Join => entry.current_join = Some(index),
            MembershipAction::Leave => entry.current_join = None,
            MembershipAction::History => {}
        }
    }
    for (person, entry) in entries {
        PERSON_MEMBERSHIP.put(store, txn, &(room, person), &entry)?;
    }
    if !rows.is_empty() {
        INDEXED_REVISION.put(store, txn, &room, &(rows.len() as u64))?;
    }
    Ok(())
}

fn drop_room_in(store: &Store, txn: &mut heed::RwTxn<'_>, room: EntityId) -> Result<()> {
    PERSON_MEMBERSHIP.delete_from(store, txn, room.as_bytes())?;
    INDEXED_REVISION.delete(store, txn, &room)?;
    Ok(())
}

/// Rebuilds every decodable ledger after restore; damaged rooms stay unindexed.
pub(crate) fn rebuild_membership_index_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
) -> Result<()> {
    let store = &vault.store;
    PERSON_MEMBERSHIP.delete_from(store, txn, &[])?;
    INDEXED_REVISION.delete_from(store, txn, &[])?;
    let rooms: Vec<EntityId> = MEMBERSHIP_SEQ
        .iter_from(store, txn, &[])?
        .filter_map(|entry| entry.ok().map(|(room, _)| room))
        .collect();
    for room in rooms {
        if let Ok(rows) = rows_in(store, txn, room) {
            rebuild_room_in(store, txn, room, &rows)?;
        }
    }
    Ok(())
}

/// Fold and index controls for tests/membership_index.rs (L6-16). Not API.
#[cfg(oneiron_test_support)]
pub(crate) mod test_support {
    use super::*;
    use crate::conversation::membership::{
        current_join_rows, ledger_rows_folded_for_test, members_at_rows, windows_rows,
    };
    use std::collections::BTreeSet;

    pub(crate) fn ledger_rows_folded() -> u64 {
        ledger_rows_folded_for_test()
    }

    pub(crate) fn folded_members_at(
        vault: &Vault,
        room: EntityId,
        at: u64,
    ) -> Result<BTreeSet<EntityId>> {
        let txn = vault.store.env.read_txn()?;
        Ok(members_at_rows(&rows_in(&vault.store, &txn, room)?, at))
    }

    pub(crate) fn folded_windows(
        vault: &Vault,
        room: EntityId,
        person: EntityId,
    ) -> Result<Vec<MembershipWindow>> {
        let txn = vault.store.env.read_txn()?;
        windows_rows(&rows_in(&vault.store, &txn, room)?, person)
    }

    pub(crate) fn folded_current_join(
        vault: &Vault,
        room: EntityId,
        person: EntityId,
    ) -> Result<Option<u64>> {
        let txn = vault.store.env.read_txn()?;
        Ok(current_join_rows(
            &rows_in(&vault.store, &txn, room)?,
            person,
        ))
    }

    pub(crate) fn folded_ever_members(vault: &Vault, room: EntityId) -> Result<BTreeSet<EntityId>> {
        let txn = vault.store.env.read_txn()?;
        Ok(rows_in(&vault.store, &txn, room)?
            .into_iter()
            .filter(|row| row.action == MembershipAction::Join)
            .map(|row| row.person)
            .collect())
    }

    pub(crate) fn drop_room_index(vault: &Vault, room: EntityId) -> Result<()> {
        let mut txn = vault.store.env.write_txn()?;
        drop_room_in(&vault.store, &mut txn, room)?;
        txn.commit()?;
        Ok(())
    }

    pub(crate) fn rebuild_index(vault: &Vault) -> Result<()> {
        let mut txn = vault.store.env.write_txn()?;
        rebuild_membership_index_in_txn(vault, &mut txn)?;
        txn.commit()?;
        Ok(())
    }

    pub(crate) fn set_ledger_revision(vault: &Vault, room: EntityId, revision: u64) -> Result<()> {
        let mut txn = vault.store.env.write_txn()?;
        MEMBERSHIP_SEQ.put(&vault.store, &mut txn, &room, &revision)?;
        txn.commit()?;
        Ok(())
    }
}
