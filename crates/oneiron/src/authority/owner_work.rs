//! Folds the owner's work requests and their results: which install is to do
//! the key, custody or root work an owner act needs, and what it did.
//!
//! A request is valid when some chain of its carrier names the key that
//! signed it, and it has effect when the one carrier rule admits that
//! carrier ([`super::owner_act_signer_admits`]) on the roster view, the same
//! on every replica; one carried while its carrier was not admitted is valid
//! and without effect, so it never stalls what descends from it. It counts on
//! this install while its carrier's removal race passes here
//! ([`Standing::owner_act_race`]), as a world edit does; a removal the owner
//! signs after it lists it as seen ([`pending_carried_by`]).
//!
//! A result is valid when the request it answers is in its parents' fold and
//! that request's named executor signed it with its install key; it has
//! effect when the carrier rule admits the executor. A request's first result
//! in causal order is its one terminal state. A later one, and the greater
//! entry hash of two concurrent ones, is valid and without effect: never two
//! terminal states.
//!
//! Per (kind, target) the fold keeps the live requests, as a grant keeps its
//! travel choices ([`super::grant_travel`]): a request replaces the live
//! requests its parents carry. A replaced request with no result is still
//! its executor's to answer, except a root request: a newer one on its
//! target supersedes it, and the owner may cancel one (`cancel`, FIX 4739).
//! Either keeps it from running and signs no result; a result signed first
//! stands.
//!
//! A root request's `seen` is [`AuthorityFold::root_work_revision`]: the
//! owner roots and the target's standing, as the deciding surface saw them.
//! A custody request's is its secret's live custody requests, compared here
//! before it joins them, and an admitted revoke is terminal for its secret
//! (`custody`).
//!
//! As for every act kind, an owner the request's parents hold removed carries
//! no say-so ([`super::owner_act::owner_live_at`], mesh contract §4), and the
//! writer and the executor each check the owner live in their own
//! transactions too. An agent's act is refused by its shape: key, custody and
//! root work is owner-only until a Grant line names it. Key work a settings
//! edit left carries that edit's own act instead, and has effect only on the
//! one judgment of its basis ([`privacy_basis`], FIX 4704). Neither op rides
//! a side branch ([`super::world_privacy::side_world`] is `None`), so every
//! proven linked machine folds both.

mod cancel;
mod custody;
mod privacy_basis;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::entity_id::EntityId;

use super::machine_standing::{InstallCounted, Mark, Standing, StandingView};
use super::*;

/// One admitted request, as its entry carried it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct WorkRequest {
    request: OwnerWorkRequest,
    /// The install key that signed it.
    key: [u8; 32],
    /// Each chain that admitted the carrier under the key at the request's
    /// parents, with the mark it was signed under there.
    marks: BTreeMap<MachineAdmitter, Mark>,
    /// This install did not admit the carrier, with its holds and staleness,
    /// at the request's parents: it never counts here.
    narrow_only: bool,
}

/// A request's one result. `Clone`, not `Copy`, as its outcome is.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OwnerWorkAnswer {
    /// The result's signed entry.
    pub(crate) entry: AuthorityEntryHash,
    pub(crate) executor: EntityId,
    pub(crate) outcome: OwnerWorkOutcome,
}

/// One (kind, target)'s requests: the live ones, and every one a later
/// request replaced.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct WorkHeads {
    live: BTreeSet<AuthorityEntryHash>,
    superseded: BTreeSet<AuthorityEntryHash>,
}

/// The fold state of every owner work request and result, merged by union.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(super) struct OwnerWorkState {
    requests: BTreeMap<AuthorityEntryHash, Arc<WorkRequest>>,
    /// Each answered request's result, keyed by the request's entry.
    results: BTreeMap<AuthorityEntryHash, OwnerWorkAnswer>,
    heads: BTreeMap<(OwnerWorkKind, EntityId), WorkHeads>,
    /// Well-signed requests and results without effect.
    refused: BTreeSet<AuthorityEntryHash>,
    /// Each secret an admitted custody revoke names: terminal for it.
    revoked: BTreeSet<EntityId>,
    /// Each root request's cancels with effect, by the request's entry
    /// (`cancel`).
    cancels: BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
}

/// One admitted request as this install reads it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct FoldedWorkRequest {
    request: OwnerWorkRequest,
    /// It counts at full strength here: its carrier's removal race passes.
    counts: bool,
}

/// The heads a root request's revision is over (CALLS ROOT_WORK_REVISION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootRevisionHeads {
    /// Every valid owner root, each by its id (two entries of one root carry
    /// the same keys, so the id stands for its record on every replica), and
    /// the target's roster revision, its accepted roster revision and the
    /// head of each anchor's chain of it. The root the change binds, and its
    /// anchor's chain of the target, are left out: their arrival is what a
    /// pin waits for and what a restore or an anchoring writes, never a
    /// change the owner did not see. The pin is local, so it is never a head.
    RootsAndTargetStanding,
}

const ROOT_WORK_REVISION: RootRevisionHeads = RootRevisionHeads::RootsAndTargetStanding;

/// Every owner work request and result, as this install folds them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedOwnerWork {
    requests: BTreeMap<AuthorityEntryHash, FoldedWorkRequest>,
    results: BTreeMap<AuthorityEntryHash, OwnerWorkAnswer>,
    /// Each (kind, target)'s live requests.
    heads: BTreeMap<(OwnerWorkKind, EntityId), BTreeSet<AuthorityEntryHash>>,
    refused: BTreeSet<AuthorityEntryHash>,
    /// Each secret an admitted custody revoke names.
    revoked: BTreeSet<EntityId>,
    /// Each root request's cancels with effect, by the request's entry.
    cancels: BTreeMap<AuthorityEntryHash, BTreeSet<AuthorityEntryHash>>,
}

impl AuthorityFold {
    /// The admitted request signed as entry `hash`, counted here or not.
    pub(crate) fn owner_work_request(
        &self,
        hash: &AuthorityEntryHash,
    ) -> Option<&OwnerWorkRequest> {
        self.owner_work
            .requests
            .get(hash)
            .map(|folded| &folded.request)
    }

    /// The admitted request signed as entry `hash` when it counts here,
    /// answered or not: what a bundle published for it proves (CALLS
    /// BUNDLE_PUBLISH_PROOF).
    pub(crate) fn counted_owner_work_request(
        &self,
        hash: &AuthorityEntryHash,
    ) -> Option<&OwnerWorkRequest> {
        self.owner_work
            .requests
            .get(hash)
            .filter(|folded| folded.counts)
            .map(|folded| &folded.request)
    }

    /// The one result of the request signed as entry `request`.
    pub(crate) fn owner_work_result(
        &self,
        request: &AuthorityEntryHash,
    ) -> Option<&OwnerWorkAnswer> {
        self.owner_work.results.get(request)
    }

    /// Whether the root request signed as entry `hash` stands answered
    /// refused here: its one terminal state, which closes it as the owner's
    /// cancel or a newer request does (FIX 5696). A refusal is only ever
    /// signed final; a root request that may still run (its root not stored
    /// yet, its material or secret not held here) has no result and stays
    /// open.
    pub(crate) fn root_request_refused(&self, hash: &AuthorityEntryHash) -> bool {
        self.owner_work_request(hash)
            .is_some_and(|request| request.kind() == OwnerWorkKind::Root)
            && self
                .owner_work_result(hash)
                .is_some_and(|answer| matches!(answer.outcome, OwnerWorkOutcome::Refused { .. }))
    }

    /// The requests that name `executor`, count here and have no result yet,
    /// ascending by entry hash: the executor's work. A root request the
    /// owner cancelled, or a newer request on its target superseded, is not
    /// (CALLS ROOT_WORK_CANCEL, ROOT_WORK_SUPERSESSION).
    pub(crate) fn pending_owner_work_for(
        &self,
        executor: EntityId,
    ) -> impl Iterator<Item = (AuthorityEntryHash, &OwnerWorkRequest)> + '_ {
        self.owner_work
            .requests
            .iter()
            .filter(move |(hash, folded)| {
                folded.counts
                    && folded.request.executor == executor
                    && !self.owner_work.results.contains_key(*hash)
                    && !cancel::closed(&self.owner_work, hash, &folded.request)
            })
            .map(|(hash, folded)| (*hash, &folded.request))
    }

    /// Owner work requests and results that are valid without effect.
    pub(crate) fn refused_owner_work(&self) -> &BTreeSet<AuthorityEntryHash> {
        &self.owner_work.refused
    }

    /// The revision a root request's `change` on `target` is for (CALLS
    /// ROOT_WORK_REVISION): [`act_revision`] under
    /// [`ROOT_WORK_REVISION_CONTEXT`] over the fold's live entries the change
    /// depends on. The recorder states it as the act's `seen`, and the target
    /// computes it again in its own writer transaction: a different value is
    /// a change the owner did not see. The request itself is never a head,
    /// so no request makes itself stale.
    pub(crate) fn root_work_revision(&self, target: EntityId, change: RootChange) -> [u8; 32] {
        match ROOT_WORK_REVISION {
            RootRevisionHeads::RootsAndTargetStanding => {
                let bound = change.root().and_then(|root| {
                    self.root_anchors
                        .iter()
                        .find(|(_, roots)| roots.contains(&root))
                        .map(|(anchor, _)| *anchor)
                });
                let roots = self
                    .root_anchors
                    .iter()
                    .filter(|(anchor, _)| Some(**anchor) != bound)
                    .flat_map(|(_, roots)| roots.iter().map(|root| root.0));
                let standing = self.machine(target).into_iter().flat_map(move |machine| {
                    machine
                        .roster
                        .iter()
                        .chain(&machine.roster_trusted)
                        .chain(
                            machine
                                .anchored
                                .iter()
                                .filter(move |(anchor, _)| Some(**anchor) != bound)
                                .map(|(_, revision)| revision),
                        )
                        .map(|revision| revision.entry)
                });
                act_revision(ROOT_WORK_REVISION_CONTEXT, roots.chain(standing))
            }
        }
    }

    /// The parents a new request or a result names: the main-log heads
    /// alone (FIX 4987). The rows the carrier's and the executor's standing
    /// rest on, a request's (kind, target) live requests and a result's
    /// request are main-log rows among those heads or their ancestors, so
    /// the fold at the heads carries them: a request replaces every live one
    /// this install folds, and a result finds its request in its causal past
    /// (`apply_result`). Naming them again would put covered rows off a
    /// checkpoint image's frontier among its parents, which only the whole
    /// history folds. Never a world's key record, which rides a side branch
    /// no main-log row may name.
    pub(crate) fn owner_work_parents(&self) -> BTreeSet<AuthorityEntryHash> {
        self.append_heads.clone()
    }
}

/// The owner work transitions, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check: each is signed by an install key, never a roster key (FIX 2222:
/// the host root acts as nobody), a cancel's too. `None` for any other op.
pub(super) fn apply_owner_work(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    hash: AuthorityEntryHash,
    view: (Option<&PinnedRoot>, InstallCounted<'_>),
) -> Option<std::result::Result<(), AuthorityFoldIssue>> {
    match &entry.op {
        AuthorityOp::OwnerWorkRequest(request) => {
            Some(apply_request(state, entry, request, hash, view))
        }
        AuthorityOp::OwnerWorkResult(result) => {
            Some(apply_result(state, entry, result, hash, view))
        }
        AuthorityOp::OwnerWorkCancel(owner_cancel) => {
            Some(cancel::apply_cancel(state, entry, owner_cancel, hash, view))
        }
        _ => None,
    }
}

/// The signer's install key, when some chain of `machine` names it and its
/// sequence moves on; the fold issue otherwise.
fn install_signer(
    standing: &Standing<'_>,
    state: &FoldState,
    entry: &AuthorityLogEntry,
    machine: EntityId,
    hash: AuthorityEntryHash,
) -> std::result::Result<[u8; 32], AuthorityFoldIssue> {
    let AuthorityKey::Ed25519(key) = entry.signer_key() else {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    };
    if !standing.names_key(machine, key) {
        return Err(AuthorityFoldIssue::SignerNotInAncestry(hash));
    }
    if state
        .seqs
        .get(entry.signer_key())
        .is_some_and(|prior| entry.seq <= *prior)
    {
        return Err(AuthorityFoldIssue::NonMonotonicSeq(hash));
    }
    Ok(*key)
}

/// A request lands as a live head of its (kind, target). The target row need
/// not have arrived first: its liveness is the writer's and the executor's,
/// never the fold's.
fn apply_request(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    request: &OwnerWorkRequest,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    // Base reality has no key and no owner work.
    if request.act.target == crate::claim::base_world_id() {
        return Err(AuthorityFoldIssue::InvalidEntry(hash));
    }
    let standing = Standing::new(state, pin, counted);
    let key = install_signer(&standing, state, entry, request.carrier, hash)?;
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(request.carrier, &key, roster);
    let marks = standing.live_signing_chains(request.carrier, entry.signer_key());
    let narrow_only =
        !standing.admits_owner_act_signer(request.carrier, &key, StandingView::Install);
    drop(standing);
    // A carrier the one rule does not admit, or an owner the request's
    // parents hold removed (mesh contract §4), records a valid request
    // without effect; so does key work whose settings edit basis the parents
    // do not admit (FIX 4704), a custody change on a revision it did not
    // see, or an active one after its secret's revoke.
    let live = admitted
        && match &request.privacy_basis {
            None => super::owner_act::owner_live_at(state, request.act.owner),
            Some(basis) => privacy_basis::privacy_key_work_basis_admits(state, request, basis),
        };
    let work = &mut state.owner_work;
    if !live || !custody::custody_request_lands(work, request) {
        work.refused.insert(hash);
        return Ok(());
    }
    let heads = work
        .heads
        .entry((request.kind(), request.act.target))
        .or_default();
    let replaced = std::mem::take(&mut heads.live);
    heads.superseded.extend(replaced);
    heads.live.insert(hash);
    custody::note_custody_revoke(work, request);
    work.requests.insert(
        hash,
        Arc::new(WorkRequest {
            request: request.clone(),
            key,
            marks,
            narrow_only,
        }),
    );
    Ok(())
}

/// A result lands as its request's one terminal state, unless the request
/// already has one here.
fn apply_result(
    state: &mut FoldState,
    entry: &AuthorityLogEntry,
    result: &OwnerWorkResult,
    hash: AuthorityEntryHash,
    (pin, counted): (Option<&PinnedRoot>, InstallCounted<'_>),
) -> std::result::Result<(), AuthorityFoldIssue> {
    let standing = Standing::new(state, pin, counted);
    let key = install_signer(&standing, state, entry, result.executor, hash)?;
    let roster = StandingView::Under(MachineAdmitter::Roster);
    let admitted = standing.admits_owner_act_signer(result.executor, &key, roster);
    drop(standing);
    let work = &mut state.owner_work;
    // The causal request-presence check (CALLS "FIX 4987 causal request
    // presence"): this state merges the result's own parents alone, never
    // the final fold, so the request's fate here is its fate in the result's
    // causal past: admitted, without effect, or no request at all. A request
    // outside that past, concurrent with the result or unseen, is invalid.
    match work.requests.get(&result.request) {
        Some(request) if request.request.executor != result.executor => {
            return Err(AuthorityFoldIssue::InvalidEntry(hash));
        }
        Some(_) => {}
        None if work.refused.contains(&result.request) => {
            work.refused.insert(hash);
            return Ok(());
        }
        None => return Err(AuthorityFoldIssue::InvalidEntry(hash)),
    }
    if !admitted || work.results.contains_key(&result.request) {
        work.refused.insert(hash);
        return Ok(());
    }
    work.results.insert(
        result.request,
        OwnerWorkAnswer {
            entry: hash,
            executor: result.executor,
            outcome: result.outcome.clone(),
        },
    );
    Ok(())
}

/// Joins two states: requests, refusals, revoked secrets and cancels by
/// union, a request superseded on either side is superseded, and of two
/// different results of one request the lesser entry hash stands, the other
/// is without effect. Two copies of one request that disagree never count
/// here.
pub(super) fn merge_owner_work(merged: &mut OwnerWorkState, right: &OwnerWorkState) {
    for (hash, request) in &right.requests {
        merged
            .requests
            .entry(*hash)
            .and_modify(|held| {
                if !Arc::ptr_eq(held, request) && **held != **request {
                    let mut disputed = WorkRequest::clone(&**held);
                    disputed.narrow_only = true;
                    *held = Arc::new(disputed);
                }
            })
            .or_insert_with(|| Arc::clone(request));
    }
    merged.refused.extend(right.refused.iter().copied());
    merged.revoked.extend(right.revoked.iter().copied());
    for (request, cancels) in &right.cancels {
        merged
            .cancels
            .entry(*request)
            .or_default()
            .extend(cancels.iter().copied());
    }
    for (request, answer) in &right.results {
        match merged.results.get(request) {
            Some(held) if held.entry == answer.entry => {}
            Some(held) => {
                let (stands, without) = if held.entry < answer.entry {
                    (held.clone(), answer.entry)
                } else {
                    (answer.clone(), held.entry)
                };
                merged.refused.insert(without);
                merged.results.insert(*request, stands);
            }
            None => {
                merged.results.insert(*request, answer.clone());
            }
        }
    }
    for (at, heads) in &right.heads {
        let held = merged.heads.entry(*at).or_default();
        held.live.extend(heads.live.iter().copied());
        held.superseded.extend(heads.superseded.iter().copied());
        let superseded = &held.superseded;
        held.live.retain(|hash| !superseded.contains(hash));
    }
}

/// The fold's view of every request and result, under this install's pin and
/// holds.
pub(super) fn folded_owner_work(
    state: &FoldState,
    pin: Option<&PinnedRoot>,
    counted: InstallCounted<'_>,
) -> FoldedOwnerWork {
    let work = &state.owner_work;
    let standing = Standing::new(state, pin, counted);
    FoldedOwnerWork {
        requests: work
            .requests
            .iter()
            .map(|(hash, folded)| {
                let counts = !folded.narrow_only
                    && standing.owner_act_race(
                        folded.request.carrier,
                        hash,
                        &folded.key,
                        &folded.marks,
                        StandingView::Install,
                    );
                (
                    *hash,
                    FoldedWorkRequest {
                        request: folded.request.clone(),
                        counts,
                    },
                )
            })
            .collect(),
        results: work.results.clone(),
        heads: work
            .heads
            .iter()
            .map(|(at, heads)| (*at, heads.live.clone()))
            .collect(),
        refused: work.refused.clone(),
        revoked: work.revoked.clone(),
        cancels: work.cancels.clone(),
    }
}

/// The request signed as entry `hash`, when `standing`'s state admits it and
/// it counts there as this install reads it: not narrowed here at its
/// parents, and its carrier's removal race passes
/// ([`Standing::owner_act_race`]). What a key record naming it among its
/// parents may do on the owner's behalf (CALLS WORLD_KEY_WRAP_AUTH).
pub(super) fn counted_request<'s>(
    standing: &Standing<'s>,
    hash: &AuthorityEntryHash,
) -> Option<&'s OwnerWorkRequest> {
    let folded = standing.state().owner_work.requests.get(hash)?;
    let counts = !folded.narrow_only
        && standing.owner_act_race(
            folded.request.carrier,
            hash,
            &folded.key,
            &folded.marks,
            StandingView::Install,
        );
    counts.then_some(&folded.request)
}

/// The requests `machine` carried that have no result yet, for its next
/// profile revision's acknowledged set
/// ([`super::world_privacy::live_edits_by`]): a removal the owner signs
/// after them keeps them counting. A root request this fold closed (the
/// owner cancelled it, or a newer request on its target superseded it) never
/// runs, so it leaves the set (FIX 5583, CALLS ROOT_WORK_CANCEL,
/// ROOT_WORK_SUPERSESSION); every open and every other request stays.
pub(super) fn pending_carried_by(
    fold: &AuthorityFold,
    machine: EntityId,
) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
    fold.owner_work
        .requests
        .iter()
        .filter(move |(hash, folded)| {
            folded.request.carrier == machine
                && !fold.owner_work.results.contains_key(*hash)
                && !cancel::closed(&fold.owner_work, hash, &folded.request)
        })
        .map(|(hash, _)| *hash)
}
