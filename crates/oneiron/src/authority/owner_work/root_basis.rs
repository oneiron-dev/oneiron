//! A root request's basis witness, checked on its target (FIX 5551): whether
//! the target's heads are the ones the owner saw, lag behind them, or moved.
//!
//! The recorder signs the heads its `seen` is the revision of with the
//! request ([`RootRevisionBasis`]); the codec holds the basis to that
//! revision exactly. The target builds the same heads from its own fold.
//! Equal revisions are [`RootBasisCheck::Same`], as before. Otherwise the
//! target's heads are compared with the witness, head by head:
//!
//! - A head here that the witness does not name, a root the owner did not
//!   see, a roster or accepted roster revision other than the witnessed one,
//!   or an anchor's chain head other than the witnessed one, is a change the
//!   owner did not see: [`RootBasisCheck::Moved`], refused as a revision
//!   mismatch, exactly as before. The roster heads are main-log rows in the
//!   request's own causal past, which the target holds once it folds the
//!   request, so they never lag.
//! - What is left are witnessed heads missing here: a root, or an anchor's
//!   chain head of the target. Each is proven lag only when this install
//!   holds no trace of it: the root is in no anchor's roots here, and the
//!   anchor's entry is neither valid in the fold nor stored. Then the
//!   request waits ([`RootBasisCheck::Lagging`]) and is checked again on the
//!   next pickup or run; a witnessed head this install holds in any other
//!   form is [`RootBasisCheck::Moved`]. Set inclusion alone proves nothing.

use super::*;
use crate::error::Result;

/// What a root request's basis is on its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootBasisCheck {
    /// The target's revision is the act's `seen`.
    Same,
    /// Every head that differs is a witnessed root or anchor's mark this
    /// install has not folded or stored yet: the request waits for them.
    Lagging,
    /// A head here the owner did not see, or a witnessed head this install
    /// holds otherwise: the roots or the target's standing moved.
    Moved,
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
    let here = fold.root_work_basis(request.act.target, change);
    if here.revision() == seen {
        return Ok(RootBasisCheck::Same);
    }
    let moved = basis.revision() != seen
        || here.roster != basis.roster
        || here.roster_trusted != basis.roster_trusted
        || !here.roots.is_subset(&basis.roots)
        || here
            .anchored
            .iter()
            .any(|(anchor, entry)| basis.anchored.get(anchor) != Some(entry));
    if moved {
        return Ok(RootBasisCheck::Moved);
    }
    let held_root =
        |root: &RecoveryRootId| fold.root_anchors.values().any(|ids| ids.contains(root));
    if basis.roots.difference(&here.roots).any(held_root) {
        return Ok(RootBasisCheck::Moved);
    }
    for (anchor, entry) in &basis.anchored {
        if here.anchored.contains_key(anchor) {
            continue;
        }
        if fold.valid_entries.contains(entry)
            || super::super::stored_authority_row(store, txn, entry)?.is_some()
        {
            return Ok(RootBasisCheck::Moved);
        }
    }
    Ok(RootBasisCheck::Lagging)
}
