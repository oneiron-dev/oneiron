//! Transaction-local visibility ledger for canonical and composed session views.
use super::{DeletionMarker, DeletionState, TombstoneStoreRead, WindowAddress, WindowDeletionRows};
use crate::side_table::{self, HexId, Raw, SideTable};
use crate::{EntityId, Vault, error::Result, store::ManifestDbs};
use heed::RoTxn;

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
        let markers = kept.and_then(|key| deletion_markers(self, txn, key));
        let state = match markers.as_deref() {
            Some(markers) => deletion_state_known(self, txn, id, markers)?,
            None => deletion_state_read(self, txn, id)?,
        };
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

/// [`deletion_state_read`] with the snapshot's marker rows already in
/// `markers`: the same reads in the same order, the marker point reads
/// answered from memory. The row itself, its window and a pending walk are
/// still read per row.
fn deletion_state_known(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    markers: &DeletionMarkers,
) -> Result<DeletionState> {
    let archived = markers.archived.contains(id);
    let stale = markers.stale.contains(id)
        || (markers.walk_pending
            && super::dependent_walk::pending_withdrawal_in(dbs, txn, id)?.is_some());
    let deleted = archived || removed_known(dbs, txn, id, markers)?;
    Ok(DeletionState {
        archived,
        deleted,
        stale,
    })
}

/// [`removed_in_txn`] with the snapshot's marker rows in `markers`.
fn removed_known(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    id: &EntityId,
    markers: &DeletionMarkers,
) -> Result<bool> {
    let raw = dbs.entities().get(txn, id.as_bytes())?;
    let marked = markers.hard_deleted.contains(id) || markers.fenced.contains(id);
    Ok(
        crate::deletion::marked_row_deleted(marked, id, raw.as_deref())?
            || markers.port_tombstones.contains(id)
            || match raw {
                Some(raw) => {
                    let window = crate::deletion::deletion_window_for_row_known(
                        dbs,
                        txn,
                        id,
                        &raw,
                        &|month: &str| -> Result<bool> { Ok(markers.world_pending(month)) },
                    )?;
                    markers.pending_at(&window, id)
                }
                None => false,
            },
    )
}

/// Most marker rows one recall loads into [`DeletionMarkers`]. Past it the
/// recall reads each row's markers by point reads, as without the sets; the
/// cap bounds the load, never an answer.
const MAX_RECALL_DELETION_MARKERS: usize = 4_096;

/// Recalls on this thread that skip loading a store's marker sets after a
/// load of that store passed [`MAX_RECALL_DELETION_MARKERS`].
const MARKER_RELOAD_AFTER_RECALLS: u64 = 32;

/// Every marker row of one committed snapshot that a row's deletion state
/// asks for by id, read with one prefix scan per family: archive (`ac:`),
/// hard delete (`dt:`), row fence (`df:`), the ports tombstone and stale
/// marks, and pending tombstones (`pt:`). A set holds exactly the ids a point
/// read of that family would find, so a row's answer is the same.
struct DeletionMarkers {
    archived: std::collections::HashSet<EntityId>,
    hard_deleted: std::collections::HashSet<EntityId>,
    fenced: std::collections::HashSet<EntityId>,
    port_tombstones: std::collections::HashSet<EntityId>,
    stale: std::collections::HashSet<EntityId>,
    /// The `pt:` key suffixes, `<window>:<hex id>`, in byte order.
    pending: Vec<Vec<u8>>,
    /// Whether any dependent walk is pending ([`super::dependent_walk::any_pending_walk`]).
    walk_pending: bool,
}

impl DeletionMarkers {
    /// The sets of the snapshot `txn` reads, or `None` past
    /// [`MAX_RECALL_DELETION_MARKERS`] rows or where a pending tombstone key
    /// does not decode, which a point read of a month's world windows reports.
    fn load(dbs: &impl ManifestDbs, txn: &RoTxn<'_>) -> Result<Option<Self>> {
        let mut rows = 0usize;
        let Some(archived) = hex_marker_ids(dbs, txn, DeletionMarker::Archive, &mut rows)? else {
            return Ok(None);
        };
        let Some(hard_deleted) = hex_marker_ids(dbs, txn, DeletionMarker::HardDelete, &mut rows)?
        else {
            return Ok(None);
        };
        let Some(fenced) = hex_marker_ids(dbs, txn, DeletionMarker::RowFence, &mut rows)? else {
            return Ok(None);
        };
        let Some(port_tombstones) =
            vault_meta_ids(dbs, txn, super::integrity::TOMBSTONE, &mut rows)?
        else {
            return Ok(None);
        };
        let Some(stale) = vault_meta_ids(dbs, txn, super::integrity::STALE, &mut rows)? else {
            return Ok(None);
        };
        let mut pending = Vec::new();
        for row in crate::deletion::PENDING_TOMBSTONE.iter_raw_from(dbs, txn, &[])? {
            let (key, _) = row?;
            rows += 1;
            if rows > MAX_RECALL_DELETION_MARKERS
                || <crate::deletion::PendingTombstoneKey as side_table::SideKey>::decode_key(&key)
                    .is_none()
            {
                return Ok(None);
            }
            pending.push(key);
        }
        pending.sort_unstable();
        Ok(Some(Self {
            archived,
            hard_deleted,
            fenced,
            port_tombstones,
            stale,
            pending,
            walk_pending: super::dependent_walk::any_pending_walk(dbs, txn)?,
        }))
    }

    /// Whether any world window of `month` holds a pending tombstone, as
    /// `port_has_world_pending_tombstone` reads it.
    fn world_pending(&self, month: &str) -> bool {
        let worlds = format!("{month}@");
        let at = self
            .pending
            .partition_point(|key| key.as_slice() < worlds.as_bytes());
        self.pending
            .get(at)
            .is_some_and(|key| key.starts_with(worlds.as_bytes()))
    }

    /// Whether the window `window` holds a pending tombstone of `id`.
    fn pending_at(&self, window: &str, id: &EntityId) -> bool {
        if self.pending.is_empty() {
            return false;
        }
        let key = format!("{window}:{}", id.to_hex());
        self.pending
            .binary_search_by(|row| row.as_slice().cmp(key.as_bytes()))
            .is_ok()
    }
}

/// The id whose canonical lower-case hex is `hex`, the only id a point read
/// of a hex-keyed marker at `hex` answers for.
fn canonical_hex_id(hex: &[u8]) -> Option<EntityId> {
    if hex.len() != 32 {
        return None;
    }
    let nibble = |digit: u8| match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        _ => None,
    };
    let mut bytes = [0u8; 16];
    for (byte, pair) in bytes.iter_mut().zip(hex.chunks_exact(2)) {
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(EntityId::from_bytes_unchecked(bytes))
}

/// The ids a hex-keyed `marker` family holds, counting each row in `rows`;
/// `None` once `rows` passes [`MAX_RECALL_DELETION_MARKERS`].
fn hex_marker_ids(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    marker: DeletionMarker,
    rows: &mut usize,
) -> Result<Option<std::collections::HashSet<EntityId>>> {
    let mut ids = std::collections::HashSet::new();
    for row in marker_table(marker).iter_raw_from(dbs, txn, &[])? {
        let (hex, _) = row?;
        *rows += 1;
        if *rows > MAX_RECALL_DELETION_MARKERS {
            return Ok(None);
        }
        // Any other key spelling is one no point read asks for.
        if let Some(id) = canonical_hex_id(&hex) {
            ids.insert(id);
        }
    }
    Ok(Some(ids))
}

/// The ids under `prefix` in `vault_meta`, keyed `prefix` + the id's 16
/// bytes, counting each row in `rows`; `None` once `rows` passes
/// [`MAX_RECALL_DELETION_MARKERS`].
fn vault_meta_ids(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    prefix: &[u8],
    rows: &mut usize,
) -> Result<Option<std::collections::HashSet<EntityId>>> {
    let mut ids = std::collections::HashSet::new();
    for row in dbs.vault_meta().prefix_iter(txn, prefix)? {
        let (key, _) = row?;
        *rows += 1;
        if *rows > MAX_RECALL_DELETION_MARKERS {
            return Ok(None);
        }
        // A key of another length is one no point read asks for.
        if let Some(bytes) = key
            .get(prefix.len()..)
            .and_then(|id| <[u8; 16]>::try_from(id).ok())
        {
            ids.insert(EntityId::from_bytes_unchecked(bytes));
        }
    }
    Ok(Some(ids))
}

/// The marker sets of the snapshot `key` names, loaded on the first deletion
/// read of a recall there, or `None` where that recall reads markers per row.
/// A load error is never kept as an answer: the row reads run instead and
/// report their own.
fn deletion_markers(
    dbs: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    key: (usize, usize),
) -> Option<std::rc::Rc<DeletionMarkers>> {
    // bench-only (L15-LEAD, never merge): L15_TRY=no_deletion_markers reads markers per row, as before.
    if crate::stage_timing::try_on("no_deletion_markers") {
        return None;
    }
    let known = DELETION_MEMO.with(|memo| {
        let memo = memo.borrow();
        match &memo.markers {
            MarkerSlot::Ready(markers) => Some(Some(std::rc::Rc::clone(markers))),
            MarkerSlot::PerRow => Some(None),
            MarkerSlot::Unloaded => memo
                .overflowed
                .is_some_and(|(store, at)| {
                    store == key.0
                        && memo.generation.wrapping_sub(at) < MARKER_RELOAD_AFTER_RECALLS
                })
                .then_some(None),
        }
    });
    if let Some(known) = known {
        return known;
    }
    let (markers, overflowed) = match DeletionMarkers::load(dbs, txn) {
        Ok(Some(markers)) => (Some(std::rc::Rc::new(markers)), false),
        Ok(None) => (None, true),
        Err(_) => (None, false),
    };
    DELETION_MEMO.with(|memo| {
        let mut memo = memo.borrow_mut();
        if memo.at != Some((key.0, key.1, true)) {
            return;
        }
        memo.markers = match &markers {
            Some(markers) => MarkerSlot::Ready(std::rc::Rc::clone(markers)),
            None => MarkerSlot::PerRow,
        };
        if overflowed {
            memo.overflowed = Some((key.0, memo.generation));
        }
    });
    markers
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
    /// The marker sets of the snapshot kept ([`deletion_markers`]).
    markers: MarkerSlot,
    /// The store whose marker load last passed the cap, and the generation
    /// it did; outlives scopes, so the next recalls there skip the load.
    overflowed: Option<(usize, u64)>,
}

/// Where the kept snapshot's marker sets stand.
#[derive(Default)]
enum MarkerSlot {
    /// No deletion read has asked for them yet.
    #[default]
    Unloaded,
    Ready(std::rc::Rc<DeletionMarkers>),
    /// This snapshot reads markers per row: past the cap, or the load failed.
    PerRow,
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
                memo.markers = MarkerSlot::Unloaded;
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
        memo.markers = MarkerSlot::Unloaded;
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
