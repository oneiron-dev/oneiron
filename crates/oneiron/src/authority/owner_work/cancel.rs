//! What keeps a root request from running (FIX 4739): the owner's cancel of
//! it, and a newer request on its target.
//!
//! A cancel is valid when some chain of its carrier names the key that
//! signed it and the request it names is in its causal past (the fold of its
//! parents), a root request of the cancel's target. It has effect when the
//! one carrier rule admits that carrier on the roster view and its owner is
//! live there ([`super::super::owner_act::owner_live_at`]), the same on every
//! replica; otherwise it is valid and without effect, as is a cancel of a
//! request without effect. A cancel only takes away: it stops work and
//! starts none, so a later removal of its carrier does not lift it.
//!
//! Neither rule signs a result, and none is made up for the recorder. A
//! request either one closes has no result: it leaves its executor's pending
//! work and the target's pending-root read, and its receipt, derived from the
//! fold, reads cancelled or superseded. A result its executor signed before
//! it folded the cancel or the newer request is the request's one terminal
//! state and stands. Nothing is ordered by clock or hash, nothing is undone,
//! nothing expires, and every request, cancel and result stays in the
//! history.

use super::*;

/// When the owner's cancel keeps a root request from running (CALLS
/// ROOT_WORK_CANCEL).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootCancel {
    /// The owner's act, carried by any install he is authenticated on, ids
    /// only, names the request. An executor whose fold holds it before it
    /// answers never runs the request, at its pickup or at its recheck
    /// before the change, however long it was offline. A result it signed
    /// before it folded the cancel stands.
    OwnerActBeforeExecution,
}

const ROOT_WORK_CANCEL: RootCancel = RootCancel::OwnerActBeforeExecution;

/// Which root requests a newer one replaces (CALLS ROOT_WORK_SUPERSESSION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootSupersession {
    /// A request on the same target whose causal past holds the older one
    /// replaces it, as the fold's live heads of the target's root requests
    /// keep them: the older never runs. Two concurrent requests replace
    /// neither, and nothing orders them by clock or hash.
    CausalNewRequestOnSameTarget,
}

const ROOT_WORK_SUPERSESSION: RootSupersession = RootSupersession::CausalNewRequestOnSameTarget;

impl AuthorityFold {
    /// Whether the owner cancelled the root request signed as entry `hash`
    /// before its executor answered it (CALLS ROOT_WORK_CANCEL): it never
    /// runs.
    pub(crate) fn root_request_cancelled(&self, hash: &AuthorityEntryHash) -> bool {
        self.owner_work
            .requests
            .get(hash)
            .is_some_and(|folded| cancelled(&self.owner_work, hash, &folded.request))
    }

    /// Whether a newer request on its target superseded the root request
    /// signed as entry `hash` before its executor answered it (CALLS
    /// ROOT_WORK_SUPERSESSION): it never runs.
    pub(crate) fn root_request_superseded(&self, hash: &AuthorityEntryHash) -> bool {
        self.owner_work
            .requests
            .get(hash)
            .is_some_and(|folded| superseded(&self.owner_work, hash, &folded.request))
    }

    /// The owner's cancels that name the request signed as entry `request`,
    /// ascending by entry, whether they came before its result or after.
    pub(crate) fn owner_work_cancels(
        &self,
        request: &AuthorityEntryHash,
    ) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
        self.owner_work
            .cancels
            .get(request)
            .into_iter()
            .flatten()
            .copied()
    }
}

/// Whether `request`, signed as entry `hash`, is a root request with no
/// result that the owner cancelled (CALLS ROOT_WORK_CANCEL).
fn cancelled(
    work: &FoldedOwnerWork,
    hash: &AuthorityEntryHash,
    request: &OwnerWorkRequest,
) -> bool {
    unanswered_root(work, hash, request)
        && match ROOT_WORK_CANCEL {
            RootCancel::OwnerActBeforeExecution => work.cancels.contains_key(hash),
        }
}

/// Whether `request`, signed as entry `hash`, is a root request with no
/// result that a newer request on its target replaced (CALLS
/// ROOT_WORK_SUPERSESSION).
fn superseded(
    work: &FoldedOwnerWork,
    hash: &AuthorityEntryHash,
    request: &OwnerWorkRequest,
) -> bool {
    unanswered_root(work, hash, request)
        && match ROOT_WORK_SUPERSESSION {
            RootSupersession::CausalNewRequestOnSameTarget => work
                .heads
                .get(&(OwnerWorkKind::Root, request.act.target))
                .is_none_or(|live| !live.contains(hash)),
        }
}

/// A root request with no result: the only kind either rule closes, and
/// only before its one terminal state.
fn unanswered_root(
    work: &FoldedOwnerWork,
    hash: &AuthorityEntryHash,
    request: &OwnerWorkRequest,
) -> bool {
    request.kind() == OwnerWorkKind::Root && !work.results.contains_key(hash)
}

/// Whether `request`, signed as entry `hash`, never runs: the owner
/// cancelled it, or a newer request on its target replaced it, before its
/// executor answered it.
pub(super) fn closed(
    work: &FoldedOwnerWork,
    hash: &AuthorityEntryHash,
    request: &OwnerWorkRequest,
) -> bool {
    cancelled(work, hash, request) || superseded(work, hash, request)
}

/// A cancel lands as the owner's word that the request it names never runs,
/// unless its carrier or owner does not stand at its parents.
pub(super) fn apply_cancel(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    cancel: &OwnerWorkCancel,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    let standing = Standing::new(state, pin, counted);
    let key = install_signer(&standing, state, entry, cancel.carrier, hash)?;
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(cancel.carrier, &key, roster);
    drop(standing);
    let live = admitted && super::super::owner_act::owner_live_at(state, cancel.act.owner);
    let work = &mut state.owner_work;
    // The causal request-presence check, as a result's: the request is in
    // the cancel's past, a root request of the cancel's own target. A cancel
    // of a request without effect there is without effect too.
    match work.requests.get(&cancel.request) {
        Some(asked)
            if asked.request.kind() != OwnerWorkKind::Root
                || asked.request.act.target != cancel.act.target =>
        {
            return Err(AuthorityFoldIssue::InvalidEntry(hash));
        }
        Some(_) => {}
        None if work.refused.contains(&cancel.request) => {
            work.refused.insert(hash);
            return Ok(());
        }
        None => return Err(AuthorityFoldIssue::InvalidEntry(hash)),
    }
    if !live {
        work.refused.insert(hash);
        return Ok(());
    }
    work.cancels.entry(cancel.request).or_default().insert(hash);
    Ok(())
}
