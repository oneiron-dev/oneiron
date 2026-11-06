//! A root request's basis witness, checked on its target (FIX 5551): whether
//! the target's heads are the ones the owner saw, lag behind them, or moved.
//!
//! The recorder signs the heads its `seen` is the revision of with the
//! request ([`RootRevisionBasis`]), and beside them, outside the revision,
//! the anchor it left out for the bound root and the parents each anchor
//! chain head's entry names ([`root_work_witness_in_txn`], FIX 6556); the
//! codec holds the heads to that revision exactly. The target builds the
//! same heads from its own fold. Equal revisions are
//! [`RootBasisCheck::Same`], as before. Otherwise the target's heads are
//! compared with the witness, head by head:
//!
//! - The anchor left out is the one this fold holds the bound root under.
//!   Where the root's record has not reached this install, it is the one
//!   the witness names, and the request waits for that record
//!   ([`RootBasisCheck::AwaitsBoundRoot`]); a witness that names another
//!   anchor than this fold holds the root under is
//!   [`RootBasisCheck::Moved`].
//! - A head here that the witness does not name, a root the owner did not
//!   see, a roster revision other than the witnessed one, or a chain head of
//!   an anchor the witness names none of, is a change the owner did not see:
//!   [`RootBasisCheck::Moved`], refused as a revision mismatch, exactly as
//!   before. The roster heads are main-log rows in the request's own causal
//!   past, which the target holds once it folds the request, so they never
//!   lag.
//! - A witnessed root missing here is proven lag only when this install
//!   holds no trace of it: the root is in no anchor's roots here.
//! - A witnessed anchor chain head this fold does not hold valid is proven
//!   lag when this install holds no trace of it and no other head of that
//!   anchor's chain, as before; or when it holds the head's signed entry,
//!   stored or carried by the image it adopted ([`SignedRows`]), and that
//!   entry waits ([`waits_on_absent_rows`]): its own signed parents are the
//!   ones the witness names, and every row beneath it this fold does not
//!   hold valid is a signed entry that waits in turn, down to rows this
//!   install holds no trace of, never an entry whose parents are all folded
//!   here. A head of that chain this fold does hold is then lag only where
//!   it is in the witnessed head's signed ancestry ([`signed_beneath`]),
//!   below folded rows too: a proof apart from the wait.
//! - An accepted roster revision other than the witnessed one is proven lag
//!   only beside such a lagging chain head of the target, and only as the
//!   standing of the target's own answers: both accepted revisions, where
//!   there are any, are answers the target carried, which stand on its own
//!   chains alone, and the witnessed one is folded here. Its standing then
//!   waits on those marks.
//!
//! Then the request waits ([`RootBasisCheck::Lagging`]) and is checked again
//! on the next pickup or run; a witnessed head this install holds in any
//! other form is [`RootBasisCheck::Moved`]. A missing record, or set
//! inclusion alone, proves nothing: a stored head proves its wait only by
//! its own signature over the parents the witness names.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use super::super::adopted_evidence::AdoptedEvidence;
use super::*;
use crate::error::Result;

/// What a root request's basis is on its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootBasisCheck {
    /// The target's revision is the act's `seen`.
    Same,
    /// Every head that differs is a witnessed root or anchor's mark this
    /// install has not folded yet, or the target's accepted roster revision
    /// whose standing waits on such a mark: the request waits for them.
    Lagging,
    /// Every head that differs is such a lag, under the bound anchor the
    /// witness names, and the bound root's record has not reached this
    /// install yet (FIX 6556): the request waits for it, as a pin awaits a
    /// root this install does not store.
    AwaitsBoundRoot,
    /// A head here the owner did not see, or a witnessed head this install
    /// holds otherwise: the roots or the target's standing moved.
    Moved,
}

/// The witness a root request on `target` carries for `change`, built from
/// this install's `fold` in the recorder's transaction `txn` (FIX 6556): the
/// heads and the bound anchor of [`AuthorityFold::root_work_basis`], and the
/// parents each anchor chain head's signed entry names, stored here or
/// carried by the image this install adopted ([`SignedRows`]). A head this
/// install holds no signed entry of, or that names no parent, gets none, and
/// a target that holds it unfolded cannot prove its wait.
pub(crate) fn root_work_witness_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
    change: RootChange,
) -> Result<RootRevisionBasis> {
    let mut basis = fold.root_work_basis(target, change);
    let mut rows = SignedRows::default();
    for entry in basis.anchored.values() {
        if let RowHere::Signed(row) = rows.read(store, txn, entry)?
            && !row.parent_hashes.is_empty()
        {
            basis
                .parents
                .insert(*entry, row.parent_hashes.iter().copied().collect());
        }
    }
    Ok(basis)
}

/// The check of `request`'s `change` and its `basis` on this install's
/// `fold`, reading `txn` for the witnessed entries the fold does not hold.
pub(crate) fn check_root_basis_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    request: &OwnerWorkRequest,
    change: RootChange,
    basis: &RootRevisionBasis,
) -> Result<RootBasisCheck> {
    let seen = request.act.seen;
    let target = request.act.target;
    let here = fold.root_work_basis(target, change);
    if here.revision() == seen {
        return Ok(RootBasisCheck::Same);
    }
    if basis.revision() != seen {
        return Ok(RootBasisCheck::Moved);
    }
    // The anchor the revision leaves out: this fold's own, unless the bound
    // root's record has not reached it and the witness names one.
    let (here, bound_root_missing) = match (basis.bound, here.bound) {
        (Some(witnessed), None) => (fold.root_work_heads(target, Some(witnessed)), true),
        (Some(witnessed), Some(derived)) if witnessed != derived => {
            return Ok(RootBasisCheck::Moved);
        }
        _ => (here, false),
    };
    let moved = here.roster != basis.roster
        || !here.roots.is_subset(&basis.roots)
        || here
            .anchored
            .keys()
            .any(|anchor| !basis.anchored.contains_key(anchor));
    if moved {
        return Ok(RootBasisCheck::Moved);
    }
    let held_root =
        |root: &RecoveryRootId| fold.root_anchors.values().any(|ids| ids.contains(root));
    if basis.roots.difference(&here.roots).any(held_root) {
        return Ok(RootBasisCheck::Moved);
    }
    let mut rows = SignedRows::default();
    let mut marks_lag = false;
    for (anchor, entry) in &basis.anchored {
        let held = here.anchored.get(anchor);
        if held == Some(entry) {
            continue;
        }
        if fold.valid_entries.contains(entry) {
            return Ok(RootBasisCheck::Moved);
        }
        let lags = match rows.read(store, txn, entry)? {
            RowHere::Absent => held.is_none(),
            RowHere::Held => false,
            RowHere::Signed(row) => {
                let signed: BTreeSet<AuthorityEntryHash> =
                    row.parent_hashes.iter().copied().collect();
                basis.parents.get(entry) == Some(&signed)
                    && waits_on_absent_rows(&mut rows, store, txn, fold, &row)?
                    && match held {
                        None => true,
                        Some(held) => signed_beneath(&mut rows, store, txn, &row, held)?,
                    }
            }
        };
        if !lags {
            return Ok(RootBasisCheck::Moved);
        }
        marks_lag = true;
    }
    if here.roster_trusted != basis.roster_trusted {
        let waits = marks_lag && accepted_roster_waits(&mut rows, store, txn, fold, target, basis)?;
        if !waits {
            return Ok(RootBasisCheck::Moved);
        }
    }
    Ok(if bound_root_missing {
        RootBasisCheck::AwaitsBoundRoot
    } else {
        RootBasisCheck::Lagging
    })
}

/// Whether the signed entry `head`, which this fold does not hold valid,
/// waits here (FIX 6556): it names a parent this fold does not hold valid,
/// and so does every signed entry beneath it that this fold does not hold
/// valid, down to rows this install holds no trace of, which are what it
/// waits on. An entry whose parents are all folded here was judged here,
/// and a row held here without a signed entry to read proves nothing: either
/// is no wait. Each row is read at most once.
fn waits_on_absent_rows(
    rows: &mut SignedRows,
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    head: &AuthorityLogEntry,
) -> Result<bool> {
    let folds_here = |entry: &AuthorityLogEntry| {
        entry
            .parent_hashes
            .iter()
            .all(|parent| fold.valid_entries.contains(parent))
    };
    if folds_here(head) {
        return Ok(false);
    }
    let mut met = BTreeSet::new();
    let mut unfolded = head.parent_hashes.clone();
    while let Some(hash) = unfolded.pop() {
        if fold.valid_entries.contains(&hash) || !met.insert(hash) {
            continue;
        }
        match rows.read(store, txn, &hash)? {
            RowHere::Absent => {}
            RowHere::Held => return Ok(false),
            RowHere::Signed(row) => {
                if folds_here(&*row) {
                    return Ok(false);
                }
                unfolded.extend(row.parent_hashes);
            }
        }
    }
    Ok(true)
}

/// Whether `held` is in the signed ancestry of `head` (FIX 6556): among its
/// parents, or beneath one through signed entries this install reads,
/// folded or not, breadth first so a recent row is found near the head. A
/// row it holds no signed entry of ends its branch, and only a row met
/// counts.
fn signed_beneath(
    rows: &mut SignedRows,
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    head: &AuthorityLogEntry,
    held: &AuthorityEntryHash,
) -> Result<bool> {
    let mut met = BTreeSet::new();
    let mut queue: VecDeque<AuthorityEntryHash> = head.parent_hashes.iter().copied().collect();
    while let Some(hash) = queue.pop_front() {
        if hash == *held {
            return Ok(true);
        }
        if !met.insert(hash) {
            continue;
        }
        if let RowHere::Signed(row) = rows.read(store, txn, &hash)? {
            queue.extend(row.parent_hashes);
        }
    }
    Ok(false)
}

/// Whether the target's accepted roster revision here and the witnessed one
/// differ only as its own answers' standing does (FIX 6556): each, where
/// there is one, is an answer the target carried, which stands on the
/// target's own chains alone, and the witnessed one is folded here. Beside a
/// lagging chain head of the target, that standing waits on the marks this
/// install has not folded yet.
fn accepted_roster_waits(
    rows: &mut SignedRows,
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
    basis: &RootRevisionBasis,
) -> Result<bool> {
    let own_answer = |carrier: Option<EntityId>| carrier == Some(target);
    if fold
        .machine(target)
        .and_then(|machine| machine.roster_trusted.as_ref())
        .is_some_and(|revision| !own_answer(revision.carrier()))
    {
        return Ok(false);
    }
    let Some(witnessed) = basis.roster_trusted else {
        return Ok(true);
    };
    if !fold.valid_entries.contains(&witnessed) {
        return Ok(false);
    }
    let RowHere::Signed(row) = rows.read(store, txn, &witnessed)? else {
        return Ok(false);
    };
    Ok(matches!(&row.op, AuthorityOp::MachineProfile(profile)
        if profile.machine == target && own_answer(profile.carrier)))
}

/// What this install holds of one authority row by its hash.
enum RowHere {
    /// Its signed entry, stored here or carried by the image this install
    /// adopted, and hashing to the row's hash: its parents are what its
    /// signature covers.
    Signed(Box<AuthorityLogEntry>),
    /// Held, but with no signed entry to read: a row the adopted image
    /// covers without carrying its body, or a stored row whose entry hashes
    /// otherwise.
    Held,
    /// No trace: neither stored nor covered by an adopted image.
    Absent,
}

/// The signed rows a basis reads (FIX 6556): each row this install stores,
/// else the body the image it adopted carries of a covered row, both
/// decoded with their signatures verified. The adopted evidence is read at
/// the first row not stored here.
#[derive(Default)]
struct SignedRows(Option<Option<Arc<AdoptedEvidence>>>);

impl SignedRows {
    /// What this install holds of the row `hash`.
    fn read(
        &mut self,
        store: &crate::store::Store,
        txn: &heed::RoTxn<'_>,
        hash: &AuthorityEntryHash,
    ) -> Result<RowHere> {
        if let Some(row) = super::super::stored_authority_row(store, txn, hash)? {
            return signed_row(row, hash);
        }
        if self.0.is_none() {
            self.0 = Some(super::super::adopted_evidence_in_txn(store, txn)?);
        }
        let Some(Some(evidence)) = &self.0 else {
            return Ok(RowHere::Absent);
        };
        if let Some(body) = evidence.body(hash) {
            return signed_row(body.clone(), hash);
        }
        Ok(if evidence.rows().contains_key(hash) {
            RowHere::Held
        } else {
            RowHere::Absent
        })
    }
}

/// `row`, read as the row `hash`: signed evidence when its entry hashes to
/// `hash`, else a row held here that proves nothing.
fn signed_row(row: AuthorityLogEntry, hash: &AuthorityEntryHash) -> Result<RowHere> {
    Ok(if authority_entry_hash(&row)? == *hash {
        RowHere::Signed(Box::new(row))
    } else {
        RowHere::Held
    })
}
