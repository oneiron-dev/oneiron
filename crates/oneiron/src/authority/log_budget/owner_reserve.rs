//! The owner's reserve under the fold's memory floor (FIX
//! [AUTHORITY-LOG-SIGNER-FLOOD]): the stored log's projected fold peak
//! the doors judge each arriving row by, and the hold the reserve's typed
//! check names.

use super::*;

/// The owner's reserve under the memory floor is the floor divided by this:
/// an eighth, so a log near an 8 GiB floor still has 1 GiB for the owner's
/// work once every other row waits. A row that is not the owner's work lands
/// only while the log with it stays under the reserve's start
/// ([`FoldProjection::bytes_with`]), so only the owner's work enters the
/// reserve. A stored row with a missing ancestor is charged at its worst
/// case, every row and missing parent of the log, from its arrival
/// (OWNER-RESERVE-ORPHAN-CHARGE = A; Astra owner-reserve F1, OPUS-SECREAD-A
/// #8360 N2), so a parent it names adds nothing for its own ancestry when it
/// lands later, the owner's or another's. One of the owner's rows then
/// projects at most 16 KiB, plus 640 bytes for each row and missing parent
/// the log with it holds (its ancestors at most), plus 640 bytes for each
/// stored row with a missing ancestor times what the owner's row adds to the
/// log's worst case: one unless a stored row names it, and one for each of
/// its parents that no row is or names. On a floor at or above the default's
/// least (1 GiB) and with few parents missing, the reserve holds about three
/// such rows when every stored row is an ancestor of each, and at least one
/// when stored rows with a missing ancestor fill the log to the reserve's
/// start (estimate: a row's 16 KiB caps the rows under the reserve's start,
/// and the rows with a missing ancestor are fewer). A floor row set to a few
/// hundred KiB can leave it too small for one.
pub(super) const FOLD_MEMORY_OWNER_RESERVE_DIVISOR: u64 = 8;

/// The projected peak past which the doors keep the rest of the memory floor
/// for the owner's work: the floor the fold reads on this install, less its
/// owner reserve ([`FOLD_MEMORY_OWNER_RESERVE_DIVISOR`]).
pub(super) fn owner_reserve_start(
    store: &Store,
    txn: &heed::RoTxn<'_>,
) -> crate::error::Result<u64> {
    let policy = authority_observation_policy_in_txn(store, txn)?;
    let floor = fold_memory_floor(Some(&policy));
    Ok(floor - floor / FOLD_MEMORY_OWNER_RESERVE_DIVISOR)
}

/// An upper bound on the peak a fold of `rows` projects
/// ([`fold_projected_bytes`]), `rows` being each stored row's entry hash, as
/// the fold keys its rows, and parents. A row's ancestor pairs are bounded
/// parents first: a row on one parent has that parent's bound and the parent
/// itself, exactly as the fold counts them; a join has the lesser of the same
/// sum over its parents and the rows bounded before it, since every ancestor
/// of it is one of them. A one-signer chain is bounded exactly.
///
/// A row with a missing ancestor, a parent no row is or a row on one, is
/// charged at its worst case: every stored row and every missing parent of
/// the log among its ancestors (OWNER-RESERVE-ORPHAN-CHARGE = A;
/// OPUS-SECREAD-A #8360 N2). The fold counts a missing parent once, but the
/// parent can bring any ancestry when it comes, and the owner's work lands
/// past the reserve unbounded; charged so from its arrival, the row gains
/// nothing when its parent lands, whoever signed it. A parent still unbounded
/// when its child is bounded closes a cycle, which no signed history holds;
/// the log is then bounded as if every row had every row and every missing
/// parent among its ancestors.
pub(super) fn stored_fold_projection(
    rows: &BTreeMap<AuthorityEntryHash, &[AuthorityEntryHash]>,
) -> FoldProjection {
    let missing = rows
        .values()
        .flat_map(|parents| parents.iter())
        .filter(|parent| !rows.contains_key(*parent))
        .copied()
        .collect::<BTreeSet<_>>();
    let most = (rows.len() as u64).saturating_add(missing.len() as u64);
    let mut bound = BTreeMap::<AuthorityEntryHash, u64>::new();
    let mut open = BTreeSet::new();
    let mut entered = BTreeSet::new();
    let mut cyclic = false;
    let mut closed_pairs = 0_u64;
    for start in rows.keys() {
        let mut stack = vec![(*start, false)];
        while let Some((hash, parents_bounded)) = stack.pop() {
            let parents = rows[&hash];
            if parents_bounded {
                let mut opens = false;
                let mut through = 0_u64;
                for parent in parents {
                    if !rows.contains_key(parent) || open.contains(parent) {
                        opens = true;
                        continue;
                    }
                    let ancestors = bound.get(parent).map_or_else(
                        || {
                            cyclic = true;
                            most
                        },
                        |ancestors| ancestors.saturating_add(1),
                    );
                    through = through.saturating_add(ancestors);
                }
                let ancestors = if opens {
                    open.insert(hash);
                    most
                } else if parents.len() == 1 {
                    through
                } else {
                    through.min(bound.len() as u64)
                };
                if !opens {
                    closed_pairs = closed_pairs.saturating_add(ancestors);
                }
                bound.insert(hash, ancestors);
            } else if entered.insert(hash) {
                stack.push((hash, true));
                stack.extend(
                    parents
                        .iter()
                        .filter(|parent| rows.contains_key(*parent) && !entered.contains(*parent))
                        .map(|parent| (*parent, false)),
                );
            }
        }
    }
    FoldProjection {
        rows: rows.len(),
        closed_pairs,
        open,
        missing,
        cyclic,
        bound,
    }
}

/// The stored log's projected fold peak ([`stored_fold_projection`]), with
/// what the door needs to bound the log with one more row in it.
#[derive(Debug)]
pub(super) struct FoldProjection {
    rows: usize,
    /// The ancestor pairs of the stored rows with no missing ancestor.
    closed_pairs: u64,
    /// The stored rows with a missing ancestor, each charged at the log's
    /// worst case ([`Self::most`]).
    open: BTreeSet<AuthorityEntryHash>,
    /// The distinct parents no stored row is.
    missing: BTreeSet<AuthorityEntryHash>,
    /// Whether the stored rows close a cycle (every row is then bounded with
    /// every row and missing parent).
    cyclic: bool,
    /// Each stored row's ancestor bound.
    bound: BTreeMap<AuthorityEntryHash, u64>,
}

impl FoldProjection {
    /// The log's worst case for one row's ancestors: every stored row and
    /// every missing parent.
    fn most(&self) -> u64 {
        (self.rows as u64).saturating_add(self.missing.len() as u64)
    }

    /// The stored log's projected ancestor pairs.
    fn pairs(&self) -> u64 {
        let most = self.most();
        if self.cyclic {
            return (self.rows as u64).saturating_mul(most);
        }
        self.closed_pairs
            .saturating_add((self.open.len() as u64).saturating_mul(most))
    }

    /// The stored log's projected peak.
    pub(super) fn bytes(&self) -> u64 {
        fold_projected_bytes(self.rows, self.pairs())
    }

    /// The projected peak with the row `hash`, on `parents`, stored too
    /// (Astra owner-reserve F1). Its own ancestors are bounded as a stored
    /// row's are, at the worst case of the log with it when one of its
    /// parents is missing or has a missing ancestor. That worst case is the
    /// one every stored row with a missing ancestor is charged: the row adds
    /// one to it unless a stored row names it, and its parents that no row
    /// is or names add one each (Astra owner-reserve r2 F1: a join names any
    /// number of those). A stored row with no missing ancestor never has the
    /// row among its ancestors, so its bound stands. Nothing else moves: a
    /// stored row that names the row was charged at its worst case when it
    /// came, so the row's own ancestry adds nothing to it (OPUS-SECREAD-A
    /// #8360 N2).
    pub(super) fn bytes_with(
        &self,
        hash: &AuthorityEntryHash,
        parents: &[AuthorityEntryHash],
    ) -> u64 {
        if self.bound.contains_key(hash) {
            return self.bytes();
        }
        let rows = self.rows.saturating_add(1);
        let fresh = parents
            .iter()
            .filter(|parent| {
                *parent != hash
                    && !self.bound.contains_key(*parent)
                    && !self.missing.contains(*parent)
            })
            .collect::<BTreeSet<_>>()
            .len() as u64;
        // The log with the row in it: it is no longer missing, and its fresh
        // parents are.
        let missing = (self.missing.len() as u64)
            .saturating_sub(u64::from(self.missing.contains(hash)))
            .saturating_add(fresh);
        let most = (rows as u64).saturating_add(missing);
        if self.cyclic {
            return fold_projected_bytes(rows, (rows as u64).saturating_mul(most));
        }
        let opens = parents
            .iter()
            .any(|parent| !self.bound.contains_key(parent) || self.open.contains(parent));
        let through = |parent: &AuthorityEntryHash| {
            self.bound
                .get(parent)
                .map_or(most, |ancestors| ancestors.saturating_add(1))
        };
        let own = match parents {
            _ if opens => most,
            [parent] => through(parent),
            _ => parents
                .iter()
                .map(through)
                .fold(0, u64::saturating_add)
                .min(self.bound.len() as u64),
        };
        let pairs = self
            .closed_pairs
            .saturating_add((self.open.len() as u64).saturating_mul(most))
            .saturating_add(own);
        fold_projected_bytes(rows, pairs)
    }
}

/// The stored log's projected fold peak as the doors judge it, kept across
/// authority generations with the door view (FIX
/// [OWNER-RESERVE-PROJECTION-COST]): each stored row's parents and the log's
/// missing parents, extended row by row, and the exact projection
/// ([`stored_fold_projection`]) built from them once per view, only where a
/// door needs it.
///
/// A door asks only whether the log, with or without an arriving row, is
/// past the reserve's start, and rows times the log's worst case
/// ([`FoldProjection::most`]) bounds its ancestor pairs from above: an open
/// row is charged that worst case; a closed row's bound is at most the rows
/// bounded before it (on one parent, its parent's and one; a join's is
/// capped there; with none, zero); and a cyclic log charges every row the
/// worst case. The same holds with the arriving row in the log, at its worst
/// case ([`FoldProjection::bytes_with`]). Where that bound is at or under the
/// start, the exact peak is too, and the answer needs no projection.
///
/// The exact projection is not extended: a join's bound is capped at the rows
/// bounded before it in a walk in hash order, so a new row whose hash sorts
/// first can move every later capped join's bound.
#[derive(Debug, Default)]
pub(super) struct DoorProjection {
    /// Each stored row's entry hash, as the fold keys its rows, and its
    /// parents.
    parents: im::OrdMap<AuthorityEntryHash, Arc<[AuthorityEntryHash]>>,
    /// The distinct parents no stored row is.
    missing: im::OrdSet<AuthorityEntryHash>,
    exact: std::sync::OnceLock<FoldProjection>,
}

impl DoorProjection {
    /// This projection with no exact peak built yet, to extend.
    pub(super) fn to_extend(&self) -> Self {
        Self {
            parents: self.parents.clone(),
            missing: self.missing.clone(),
            exact: std::sync::OnceLock::new(),
        }
    }

    /// Adds the stored row `hash` on `parents`.
    pub(super) fn insert(&mut self, hash: AuthorityEntryHash, parents: &[AuthorityEntryHash]) {
        self.parents.insert(hash, parents.into());
        self.missing.remove(&hash);
        for parent in parents {
            if !self.parents.contains_key(parent) {
                self.missing.insert(*parent);
            }
        }
    }

    /// Whether the row `hash` is stored.
    pub(super) fn stores(&self, hash: &AuthorityEntryHash) -> bool {
        self.parents.contains_key(hash)
    }

    /// The exact projection, built on its first read.
    pub(super) fn exact(&self) -> &FoldProjection {
        self.exact.get_or_init(|| {
            let rows = self
                .parents
                .iter()
                .map(|(hash, parents)| (*hash, &**parents))
                .collect();
            stored_fold_projection(&rows)
        })
    }

    /// The stored log's projected peak.
    pub(super) fn bytes(&self) -> u64 {
        self.exact().bytes()
    }

    /// The stored log's projected peak where it is past `start`, else None.
    pub(super) fn bytes_past(&self, start: u64) -> Option<u64> {
        let rows = self.parents.len();
        let most = (rows as u64).saturating_add(self.missing.len() as u64);
        if fold_projected_bytes(rows, (rows as u64).saturating_mul(most)) <= start {
            return None;
        }
        let bytes = self.bytes();
        (bytes > start).then_some(bytes)
    }

    /// The projected peak with the row `hash`, on `parents`, stored too
    /// ([`FoldProjection::bytes_with`]) where it is past `start`, else None.
    pub(super) fn bytes_with_past(
        &self,
        start: u64,
        hash: &AuthorityEntryHash,
        parents: &[AuthorityEntryHash],
    ) -> Option<u64> {
        if self.stores(hash) {
            return self.bytes_past(start);
        }
        let rows = self.parents.len().saturating_add(1);
        let fresh = parents
            .iter()
            .filter(|parent| {
                *parent != hash && !self.stores(parent) && !self.missing.contains(*parent)
            })
            .collect::<BTreeSet<_>>()
            .len() as u64;
        let most = (rows as u64)
            .saturating_add(self.missing.len() as u64)
            .saturating_sub(u64::from(self.missing.contains(hash)))
            .saturating_add(fresh);
        if fold_projected_bytes(rows, (rows as u64).saturating_mul(most)) <= start {
            return None;
        }
        let bytes = self.exact().bytes_with(hash, parents);
        (bytes > start).then_some(bytes)
    }
}

/// The largest wait at the owner's reserve this handle saw, and the fold
/// peak the log with it projects (Astra owner-reserve r2 F4). The door judges
/// the log with the arriving row in it, so a held row leaves the stored log
/// under the reserve's start; so does carried owner work that rolled back
/// (r3 F3). The reserve's typed check reads this hold while it stands
/// ([`Self::stands`]). A smaller wait never takes the place of a larger one
/// that stands (r3 F2), so the check names the reserve while its largest
/// wait does not fit, and a wait no peer sends again keeps it named until
/// the handle closes. Kept per handle and never persisted: a replica's next
/// drain, and the owner's next import, hold the row again.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OwnerReserveHold {
    /// The held row, or the request whose carried work rolled back.
    pub(super) entry: AuthorityEntryHash,
    /// Whether `entry` is a request whose carried work rolled back.
    pub(super) work: bool,
    pub(super) projected: u64,
}

impl OwnerReserveHold {
    /// Whether the hold still names a wait under `projection`, the stored
    /// log's: a held row until it is stored, carried work until it lands
    /// ([`carried_work_past_owner_reserve_in_txn`]) or its request leaves
    /// this install's work ([`end_owner_reserve_work_hold`]).
    pub(super) fn stands(&self, projection: &DoorProjection) -> bool {
        self.work || !projection.stores(&self.entry)
    }
}

/// Records `hold` on `store`'s handle unless a larger hold stands under
/// `projection` (Astra owner-reserve r3 F2).
pub(super) fn hold_at_owner_reserve(
    store: &Store,
    projection: &DoorProjection,
    hold: OwnerReserveHold,
) {
    if let Ok(mut held) = store.authority_owner_reserve_hold.lock() {
        let larger_stands =
            held.is_some_and(|held| held.projected > hold.projected && held.stands(projection));
        if !larger_stands {
            *held = Some(hold);
        }
    }
}

/// The reserve's part of [`authority_door`]'s verdict on a row not stored
/// yet that a vouched key signed: the log with `entry` in it passes the
/// reserve's start and `entry` is not the owner's work ([`owner_work`]).
/// Records the hold the reserve's typed check names.
pub(super) fn held_at_owner_reserve(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    view: &AuthorityDoorView,
    row: &FoldRow,
    fold: &DoorFold<'_>,
) -> crate::error::Result<bool> {
    let hash = row.hash()?;
    let start = owner_reserve_start(store, txn)?;
    let Some(with_entry) = view
        .projection
        .bytes_with_past(start, &hash, row.parent_hashes())
    else {
        return Ok(false);
    };
    if owner_work(store, txn, &view.structure, fold, &hash, row)? {
        return Ok(false);
    }
    hold_at_owner_reserve(
        store,
        &view.projection,
        OwnerReserveHold {
            entry: hash,
            work: false,
            projected: with_entry,
        },
    );
    Ok(true)
}

/// Whether the store door holds `entry` on `txn` at the owner's reserve,
/// for that alone: never a row already stored, one no key that may vouch
/// signed, a stranger's row past the shared bound or a handoff no slip
/// issuer signed ([`authority_door`]). The owner's history import keeps
/// such a row as evidence and lands the rest (FIX
/// [OWNER-RESERVE-IMPORT-PARTIAL]).
pub(crate) fn held_at_owner_reserve_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    row: &FoldRow,
    fold: DoorFold<'_>,
) -> crate::error::Result<bool> {
    #[cfg(any(test, oneiron_test_support))]
    if DOOR_OPEN_FOR_TEST.with(std::cell::Cell::get) {
        return Ok(false);
    }
    if authority_row_resident(store, txn, row)? {
        return Ok(false);
    }
    let view = door_view(store, txn)?;
    if !view.structure.vouches_for(row) || !row_signatures_verified(row) {
        return Ok(false);
    }
    held_at_owner_reserve(store, txn, &view, row, &fold)
}
