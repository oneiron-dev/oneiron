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
//! its executor's to answer.
//!
//! The fold reads no owner or Grant liveness, for this act kind as for every
//! other one: the writer and the executor check that the owner is live in
//! their own transactions. Neither op rides a side branch
//! ([`super::world_privacy::side_world`] is `None`), so every proven linked
//! machine folds both.

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

/// A request's one result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
}

/// One admitted request as this install reads it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct FoldedWorkRequest {
    request: OwnerWorkRequest,
    /// It counts at full strength here: its carrier's removal race passes.
    counts: bool,
}

/// Every owner work request and result, as this install folds them.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FoldedOwnerWork {
    requests: BTreeMap<AuthorityEntryHash, FoldedWorkRequest>,
    results: BTreeMap<AuthorityEntryHash, OwnerWorkAnswer>,
    /// Each (kind, target)'s live requests.
    heads: BTreeMap<(OwnerWorkKind, EntityId), BTreeSet<AuthorityEntryHash>>,
    refused: BTreeSet<AuthorityEntryHash>,
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

    /// The one result of the request signed as entry `request`.
    pub(crate) fn owner_work_result(
        &self,
        request: &AuthorityEntryHash,
    ) -> Option<&OwnerWorkAnswer> {
        self.owner_work.results.get(request)
    }

    /// The requests that name `executor`, count here and have no result yet,
    /// ascending by entry hash: the executor's work.
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
            })
            .map(|(hash, folded)| (*hash, &folded.request))
    }

    /// Owner work requests and results that are valid without effect.
    pub(crate) fn refused_owner_work(&self) -> &BTreeSet<AuthorityEntryHash> {
        &self.owner_work.refused
    }

    /// The parents a new request names: the main-log heads, the rows the
    /// carrier's and the executor's standing rest on, and the live requests
    /// of its (kind, target), so it replaces every one this install folds.
    pub(crate) fn owner_work_request_parents(
        &self,
        carrier: EntityId,
        executor: EntityId,
        kind: OwnerWorkKind,
        target: EntityId,
    ) -> BTreeSet<AuthorityEntryHash> {
        let mut parents = self.append_heads.clone();
        parents.extend(standing_rows(self, carrier));
        parents.extend(standing_rows(self, executor));
        parents.extend(
            self.owner_work
                .heads
                .get(&(kind, target))
                .into_iter()
                .flatten()
                .copied(),
        );
        parents
    }

    /// The parents a result names: the request, the main-log heads and the
    /// rows the executor's standing rests on. Never a world's key record,
    /// which rides a side branch no main-log row may name.
    pub(crate) fn owner_work_result_parents(
        &self,
        request: AuthorityEntryHash,
        executor: EntityId,
    ) -> BTreeSet<AuthorityEntryHash> {
        let mut parents = self.append_heads.clone();
        parents.extend(standing_rows(self, executor));
        parents.insert(request);
        parents
    }
}

/// The owner work transitions, after the shape, signature, retired,
/// sequence-floor, parent-merge and vault checks and before any roster
/// check: each is signed by an install key, never a roster key (FIX 2222:
/// the host root acts as nobody). `None` for any other op.
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
    let work = &mut state.owner_work;
    if !admitted {
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
    work.requests.insert(
        hash,
        Arc::new(WorkRequest {
            request: *request,
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
    // The request is among the result's parents (its shape check), so its
    // fate is in this state: admitted, without effect, or no request at all.
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
            outcome: result.outcome,
        },
    );
    Ok(())
}

/// Joins two states: requests and refusals by union, a request superseded
/// on either side is superseded, and of two different results of one
/// request the lesser entry hash stands, the other is without effect. Two
/// copies of one request that disagree never count here.
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
    for (request, answer) in &right.results {
        match merged.results.get(request).copied() {
            Some(held) if held.entry == answer.entry => {}
            Some(held) => {
                let (stands, without) = if held.entry < answer.entry {
                    (held, *answer)
                } else {
                    (*answer, held)
                };
                merged.refused.insert(without.entry);
                merged.results.insert(*request, stands);
            }
            None => {
                merged.results.insert(*request, *answer);
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
                        request: folded.request,
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
    }
}

/// The requests `machine` carried that have no result yet, for its next
/// profile revision's acknowledged set
/// ([`super::world_privacy::live_edits_by`]): a removal the owner signs
/// after them keeps them counting.
pub(super) fn pending_carried_by(
    fold: &AuthorityFold,
    machine: EntityId,
) -> impl Iterator<Item = AuthorityEntryHash> + '_ {
    fold.owner_work
        .requests
        .iter()
        .filter(move |(hash, folded)| {
            folded.request.carrier == machine && !fold.owner_work.results.contains_key(*hash)
        })
        .map(|(hash, _)| *hash)
}
