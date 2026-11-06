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
//!   anchor's chain, as before; or when it is stored here and waits
//!   ([`head_waits`]): its own signed parents are the ones the witness names,
//!   and every row beneath it this fold does not hold valid is stored and
//!   waits in turn, down to rows this install does not hold at all, never a
//!   stored row whose parents are all folded here. A head of that chain this
//!   fold does hold is then lag only as a folded row that walk met beneath
//!   the witnessed head.
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

use std::collections::BTreeSet;

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
/// parents each anchor chain head's stored entry names. A head this install
/// does not store, or that names no parent, gets none, and a target that
/// stores it unfolded cannot prove its wait.
pub(crate) fn root_work_witness_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    target: EntityId,
    change: RootChange,
) -> Result<RootRevisionBasis> {
    let mut basis = fold.root_work_basis(target, change);
    for entry in basis.anchored.values() {
        if let Some(row) = stored_row(store, txn, entry)?
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
    let mut marks_lag = false;
    for (anchor, entry) in &basis.anchored {
        let held = here.anchored.get(anchor);
        if held == Some(entry) {
            continue;
        }
        if fold.valid_entries.contains(entry) {
            return Ok(RootBasisCheck::Moved);
        }
        let lags = match head_waits(store, txn, fold, entry, basis.parents.get(entry))? {
            HeadHere::Absent => held.is_none(),
            HeadHere::Waits { beneath } => held.is_none_or(|held| beneath.contains(held)),
            HeadHere::Otherwise => false,
        };
        if !lags {
            return Ok(RootBasisCheck::Moved);
        }
        marks_lag = true;
    }
    if here.roster_trusted != basis.roster_trusted {
        let waits = marks_lag && accepted_roster_waits(store, txn, fold, target, basis)?;
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

/// What this install holds of a witnessed anchor chain head its fold does
/// not hold valid.
enum HeadHere {
    /// No trace: not stored here.
    Absent,
    /// Stored with the parents the witness names, and waiting on rows this
    /// install does not hold; `beneath` is every row the walk met that this
    /// fold holds valid.
    Waits {
        beneath: BTreeSet<AuthorityEntryHash>,
    },
    /// Stored, and either the witness names no parents for it, or names
    /// others than its signed entry does, or it or a row beneath it would
    /// have folded here: it was judged otherwise.
    Otherwise,
}

/// Whether the witnessed head `entry`, which this fold does not hold valid,
/// is stored here and waits (FIX 6556): its own signed parents are
/// `witnessed`, and every stored row the walk from them meets that this fold
/// does not hold valid names a parent the fold does not hold valid either.
/// The walk reads each row at most once and ends at rows this fold holds
/// valid and rows not stored here, which are what it waits on.
fn head_waits(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    fold: &AuthorityFold,
    entry: &AuthorityEntryHash,
    witnessed: Option<&BTreeSet<AuthorityEntryHash>>,
) -> Result<HeadHere> {
    let Some(row) = stored_row(store, txn, entry)? else {
        return Ok(HeadHere::Absent);
    };
    let signed: BTreeSet<AuthorityEntryHash> = row.parent_hashes.iter().copied().collect();
    if witnessed != Some(&signed) {
        return Ok(HeadHere::Otherwise);
    }
    let mut beneath = BTreeSet::new();
    let mut met = BTreeSet::from([*entry]);
    let mut stored = vec![row];
    while let Some(row) = stored.pop() {
        if row
            .parent_hashes
            .iter()
            .all(|parent| fold.valid_entries.contains(parent))
        {
            return Ok(HeadHere::Otherwise);
        }
        for parent in &row.parent_hashes {
            if !met.insert(*parent) {
                continue;
            }
            if fold.valid_entries.contains(parent) {
                beneath.insert(*parent);
            } else if let Some(row) = stored_row(store, txn, parent)? {
                stored.push(row);
            }
        }
    }
    Ok(HeadHere::Waits { beneath })
}

/// Whether the target's accepted roster revision here and the witnessed one
/// differ only as its own answers' standing does (FIX 6556): each, where
/// there is one, is an answer the target carried, which stands on the
/// target's own chains alone, and the witnessed one is folded here. Beside a
/// lagging chain head of the target, that standing waits on the marks this
/// install has not folded yet.
fn accepted_roster_waits(
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
    Ok(stored_row(store, txn, &witnessed)?.is_some_and(|row| {
        matches!(&row.op, AuthorityOp::MachineProfile(profile)
            if profile.machine == target && own_answer(profile.carrier))
    }))
}

/// The authority row stored here at `hash`, when the entry it holds hashes
/// to `hash`: a signed entry, whose parents its signature covers.
fn stored_row(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    hash: &AuthorityEntryHash,
) -> Result<Option<AuthorityLogEntry>> {
    let Some(row) = super::super::stored_authority_row(store, txn, hash)? else {
        return Ok(None);
    };
    Ok((authority_entry_hash(&row)? == *hash).then_some(row))
}
