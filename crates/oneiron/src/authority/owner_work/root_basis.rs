//! A root request's basis, checked on its target (FIX 5551): whether the
//! target's roster heads are the ones the owner saw, or moved.
//!
//! The basis is the target's roster head and accepted-roster head as the
//! recorder folded them ([`RootRevisionBasis`]), signed with the request as
//! its witness; its revision is the act's `seen`. The target recomputes the
//! same two heads from its own fold: equal revisions are
//! [`RootBasisCheck::Same`], anything else is [`RootBasisCheck::Moved`],
//! refused as a revision mismatch.

use super::*;

/// What a root request's basis is on its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootBasisCheck {
    /// The target's roster heads are the ones the owner saw: the recomputed
    /// revision is the act's `seen`.
    Same,
    /// They are not: the target's roster heads moved since the owner
    /// recorded the request, or the basis is not the revision the act saw.
    Moved,
}

/// The check of `request`'s `basis` on this install's `fold`: the basis is
/// the revision the act saw, and the target's roster heads here are still
/// the ones the owner saw. Pure: it reads the fold alone, no store.
pub(crate) fn check_root_basis(
    fold: &AuthorityFold,
    request: &OwnerWorkRequest,
    basis: &RootRevisionBasis,
) -> RootBasisCheck {
    let seen = request.act.seen;
    if basis.revision() != seen {
        return RootBasisCheck::Moved;
    }
    let here = fold.root_work_basis(request.act.target);
    if here.revision() == seen {
        RootBasisCheck::Same
    } else {
        RootBasisCheck::Moved
    }
}
