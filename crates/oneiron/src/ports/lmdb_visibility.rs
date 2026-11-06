//! Transaction-local visibility ledger for canonical and composed session views.
use super::{DeletionMarker, DeletionState, TombstoneStoreRead, WindowAddress, WindowDeletionRows};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::{EntityId, Vault, error::Result, store::ManifestDbs};
use heed::RoTxn;
use std::collections::BTreeSet;

/// The `sync_state` table of one deletion family; each is keyed by the row id.
fn marker_table(marker: DeletionMarker) -> SideTable<HexId, Vec<u8>, Raw> {
    SideTable::new(match marker {
        DeletionMarker::Archive => &side_table::DELETION_ARCHIVE_MARKER,
        DeletionMarker::HardDelete => &side_table::DELETION_HARD_DELETE_MARKER,
        DeletionMarker::RowFence => &side_table::DELETION_ROW_FENCE,
        DeletionMarker::IdentitySoftDelete => &side_table::DELETION_IDENTITY_SOFT_DELETE_MARKER,
        DeletionMarker::WindowAddress => &side_table::DELETION_WINDOW_LABEL,
    })
}
impl<T: ManifestDbs> TombstoneStoreRead for T {
    fn port_tombstone_records<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        family: super::DeletionFamily,
    ) -> Result<super::PortRows<'a, (EntityId, crate::deletion::DecodedTombstoneValue)>> {
        let prefix = match family {
            super::DeletionFamily::Archive => crate::deletion::ARCHIVE_TOMBSTONE_PREFIX,
            super::DeletionFamily::HardDelete => crate::deletion::LOCAL_HARD_DELETE_PREFIX,
        };
        Ok(Box::new(
            self.sync_state()
                .prefix_iter(txn, prefix)?
                .filter_map(move |row| {
                    let (key, value) = match row {
                        Ok(row) => row,
                        Err(error) => return Some(Err(error)),
                    };
                    let id = key
                        .strip_prefix(prefix)
                        .and_then(|hex| EntityId::from_hex(hex).ok())?;
                    Some(Ok((id, crate::deletion::decode_tombstone_value(&value))))
                }),
        ))
    }

    fn port_deletion_state(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<DeletionState> {
        let kept = deletion_memo_key(self, txn);
        if let Some(key) = kept
            && let Some(state) = DELETION_MEMO.with(|memo| memo.borrow().get(key, id))
        {
            return Ok(state);
        }
        let state = deletion_state_read(self, txn, id)?;
        if let Some(key) = kept {
            DELETION_MEMO.with(|memo| memo.borrow_mut().put(key, *id, state));
        }
        Ok(state)
    }

    fn port_deletion_marker(
        &self,
        txn: &RoTxn<'_>,
        marker: DeletionMarker,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        marker_table(marker).get_bytes(self, txn, &HexId(*id))
    }

    fn port_deletion_marked(
        &self,
        txn: &RoTxn<'_>,
        marker: DeletionMarker,
        id: &EntityId,
    ) -> Result<bool> {
        marker_table(marker).contains(self, txn, &HexId(*id))
    }
}

/// Every hard-delete marker id in this transaction, including marker-only erasures.
pub(crate) fn hard_erased_ids_in_txn(
    dbs: &impl ManifestDbs,
    rtxn: &heed::RoTxn<'_>,
) -> Result<BTreeSet<EntityId>> {
    let mut ids = BTreeSet::new();
    for row in marker_table(DeletionMarker::HardDelete).iter_raw_from(dbs, rtxn, &[])? {
        let (key, _) = row?;
        // A key that spells no id names no actor.
        if let Some(id) = std::str::from_utf8(&key)
            .ok()
            .and_then(|hex| EntityId::from_hex(hex).ok())
        {
            ids.insert(id);
        }
    }
    Ok(ids)
}

/// Whether an existing, readable row proves that `id` is not an actor.
pub(crate) fn names_no_actor_in_txn(
    dbs: &impl ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    if let Some(raw) = super::EntityStoreRead::port_entity_raw(dbs, txn, id)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// The row's deletion state as `dbs` reads it in `txn`: its archive marker,
/// its stale mark, and whether anything else deletes it ([`removed_in_txn`]).
fn deletion_state_read(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<DeletionState> {
    let archived = dbs
        .sync_state()
        .get(txn, crate::deletion::archive_tombstone_key(id).as_str())?
        .is_some();
    let stale = super::integrity::stale_in_txn(dbs, txn, id)?;
    let deleted = archived || removed_in_txn(dbs, txn, id)?;
    Ok(DeletionState {
        archived,
        deleted,
        stale,
    })
}

thread_local! {
    /// The deletion states one recall on this thread has read
    /// ([`deletion_memo_scope`]).
    static DELETION_MEMO: std::cell::RefCell<DeletionMemo> =
        std::cell::RefCell::new(DeletionMemo::default());
}

/// Deletion states kept for one committed snapshot of one store, while a
/// recall's scope is open on this thread. A state reads only that snapshot
/// (markers, the stale mark, the row and its window's pending tombstone),
/// never a clock, so the stages of one recall that ask about one row again
/// share its answer.
#[derive(Default)]
struct DeletionMemo {
    /// Open recall scopes on this thread; the memo keeps nothing outside one.
    scopes: usize,
    /// Counts the outermost scopes opened on this thread, so a memo keyed by
    /// [`recall_memo_key`] never carries an answer from one recall to the next.
    generation: u64,
    /// The store (its policy-fold cache's address) and snapshot kept, and
    /// whether that snapshot may keep states.
    at: Option<(usize, usize, bool)>,
    states: std::collections::HashMap<EntityId, DeletionState>,
}

impl DeletionMemo {
    fn get(&self, key: (usize, usize), id: &EntityId) -> Option<DeletionState> {
        (self
            .at
            .is_some_and(|(store, snapshot, keeps)| keeps && (store, snapshot) == key))
        .then(|| self.states.get(id).copied())
        .flatten()
    }

    fn put(&mut self, key: (usize, usize), id: EntityId, state: DeletionState) {
        if self
            .at
            .is_some_and(|(store, snapshot, keeps)| keeps && (store, snapshot) == key)
        {
            self.states.insert(id, state);
        }
    }
}

/// Opens a recall's deletion-state scope on this thread: until the guard
/// drops, deletion states read in a committed snapshot of a base store are
/// kept and read back. Scopes nest; the last to close empties the memo.
pub(crate) fn deletion_memo_scope() -> DeletionMemoScope {
    DELETION_MEMO.with(|memo| {
        let mut memo = memo.borrow_mut();
        if memo.scopes == 0 {
            memo.generation = memo.generation.wrapping_add(1);
        }
        memo.scopes += 1;
    });
    DeletionMemoScope { _private: () }
}

/// The guard [`deletion_memo_scope`] returns.
pub(crate) struct DeletionMemoScope {
    _private: (),
}

impl Drop for DeletionMemoScope {
    fn drop(&mut self) {
        DELETION_MEMO.with(|memo| {
            let mut memo = memo.borrow_mut();
            memo.scopes = memo.scopes.saturating_sub(1);
            if memo.scopes == 0 {
                memo.at = None;
                memo.states.clear();
            }
        });
    }
}

/// The key another per-recall memo keeps a pure snapshot answer under:
/// this recall's scope, the store and the committed snapshot `txn` reads
/// through `dbs`, or `None` where [`deletion_memo_key`] keeps nothing (no
/// scope, a write, a composed view, a snapshot not the committed one).
pub(crate) fn recall_memo_key(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
) -> Option<(u64, usize, usize)> {
    let (store, snapshot) = deletion_memo_key(dbs, txn)?;
    Some((
        DELETION_MEMO.with(|memo| memo.borrow().generation),
        store,
        snapshot,
    ))
}

/// The memo key for `txn` read through `dbs`, or `None` when nothing may be
/// kept: no recall scope is open, a write is open on this thread (its staged
/// rows move under it, and an aborted write's id is reused), `dbs` is a
/// composed view (its overlay moves no snapshot id), or a probe shows `txn`
/// does not read its store's committed snapshot, which a write transaction
/// (one past it) never does. As the policy fold's per-snapshot cache; the
/// probe runs once per snapshot, on its own thread, since a second read
/// transaction on this one fails while `txn` lives.
fn deletion_memo_key(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Option<(usize, usize)> {
    if crate::store::active_write_txn_depth() > 0 {
        return None;
    }
    let (fold_cache, env) = dbs.policy_fold_cache()?;
    let key = (std::ptr::from_ref(fold_cache) as usize, txn.id());
    DELETION_MEMO.with(|memo| {
        let mut memo = memo.borrow_mut();
        if memo.scopes == 0 {
            return None;
        }
        if let Some((store, snapshot, keeps)) = memo.at
            && (store, snapshot) == key
        {
            return keeps.then_some(key);
        }
        memo.states.clear();
        let committed = std::thread::scope(|scope| {
            scope
                .spawn(|| env.read_txn().ok().map(|committed| committed.id()))
                .join()
                .ok()
                .flatten()
        });
        let keeps = committed == Some(key.1);
        memo.at = Some((key.0, key.1, keeps));
        keeps.then_some(key)
    })
}

/// Whether something other than an archive deletes the row `id`. An archive
/// is a local visibility marker that keeps the row whole; this is the rest of
/// [`DeletionState::deleted`].
pub(crate) fn removed_in_txn(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let raw = dbs.entities().get(txn, id.as_bytes())?;
    // Every answer is an indexed marker; no window document is decoded.
    // The row's own deletion, applied here or accepted and awaiting its
    // retry, is its `df:` fence (or `dt:` once hard), whatever the payload
    // length or a window's mutable tombstone map say.
    Ok(
        crate::deletion::row_deletion_marked(dbs, txn, id, raw.as_deref())?
            || dbs
                .vault_meta()
                .get(txn, &super::integrity::tombstone_key(id))?
                .is_some()
            || match raw {
                // A local delete whose publication is pending.
                Some(raw) => {
                    let window = crate::deletion::deletion_window_for_row(dbs, txn, id, &raw)?;
                    dbs.port_pending_tombstone_present(txn, WindowAddress::new(&window), id)?
                }
                None => false,
            },
    )
}
/// Whether an owner is gone in `txn`: row removal other than an archive,
/// hard deletion, or identity soft deletion. Callers keep their own policy
/// for a marker read error.
pub(crate) fn owner_gone_in_txn(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    owner: &EntityId,
) -> Result<bool> {
    Ok(removed_in_txn(dbs, txn, owner)?
        || dbs.port_deletion_marked(txn, DeletionMarker::HardDelete, owner)?
        || dbs.port_deletion_marked(txn, DeletionMarker::IdentitySoftDelete, owner)?)
}

impl TombstoneStoreRead for Vault {
    fn port_tombstone_records<'a>(
        &self,
        txn: &'a RoTxn<'_>,
        family: super::DeletionFamily,
    ) -> Result<super::PortRows<'a, (EntityId, crate::deletion::DecodedTombstoneValue)>> {
        self.store.port_tombstone_records(txn, family)
    }

    fn port_deletion_state(&self, txn: &RoTxn<'_>, id: &EntityId) -> Result<DeletionState> {
        self.store.port_deletion_state(txn, id)
    }

    fn port_deletion_marker(
        &self,
        txn: &RoTxn<'_>,
        marker: DeletionMarker,
        id: &EntityId,
    ) -> Result<Option<Vec<u8>>> {
        self.store.port_deletion_marker(txn, marker, id)
    }

    fn port_deletion_marked(
        &self,
        txn: &RoTxn<'_>,
        marker: DeletionMarker,
        id: &EntityId,
    ) -> Result<bool> {
        self.store.port_deletion_marked(txn, marker, id)
    }
}
