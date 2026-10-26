//! Freezing one automatic mirror push plan (FIX 6866 part 2; CALLS "FIX 6866
//! automatic review record" and "FIX 6866 automatic unknown tip").
//!
//! Before anything goes out, a `schedule` or `full_auto` run reads every ref
//! it would touch at the mirror with the mirror's own credential, reviews
//! each update (`mirror_review`), cuts the refs into the mirror push's
//! batches (updates first, then deletions, at most 256 a batch), binds it
//! all in one digest and writes it in one transaction, fenced on the mirror
//! row it read and refused while another plan is open. No approval step:
//! the strategy is the standing authority, and the review is its record. A
//! read that fails marks each ref `unknown`, so it goes unleased and its
//! section covers the whole closure: never a guessed absence and never a
//! hold. A review or plan write that fails ends the run before any ref goes
//! out (the caller's hold).

use std::path::Path;

use super::mirror_plan_types::{
    MirrorBatchClaim, MirrorBatchProgress, MirrorObservedTip, MirrorPendingHead, MirrorPlanRef,
    MirrorPushPlan, MirrorRefOutcome,
};
use super::mirror_review::RefSection;
use super::review::field;
use super::types::OriginPublishDestination;
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::git_wire::{GitOid, GitRefName, GitWire, GitWireRepo, MIRROR_PUSH_REFSPECS};
use crate::origin::mirror::OriginMirrorTarget;
use crate::origin::mirror_strategy::OriginMirrorSyncStrategy;

/// A plan digest's BLAKE3 derive-key context.
const ORIGIN_MIRROR_PLAN_DIGEST_CONTEXT: &str = "oneiron:origin-mirror-plan:v1";

/// A vector digest's BLAKE3 derive-key context.
const ORIGIN_MIRROR_VECTOR_DIGEST_CONTEXT: &str = "oneiron:origin-mirror-vector:v1";

/// What one run would send: each `(ref, object)` pushed, in published order,
/// each ref deleted, and each full-auto head held for checks with the green
/// ancestor sent in its place, if any.
pub(crate) struct MirrorSelection {
    pub(crate) vector: Vec<(GitRefName, GitOid)>,
    pub(crate) deletions: Vec<GitRefName>,
    pub(crate) pending: Vec<(GitRefName, GitOid, Option<GitOid>)>,
}

impl MirrorSelection {
    /// The digest of what the selection sends, which a full-auto mirror
    /// compares with the plan it settled last.
    pub(crate) fn vector_digest(&self) -> String {
        let mut hasher = blake3::Hasher::new_derive_key(ORIGIN_MIRROR_VECTOR_DIGEST_CONTEXT);
        for (name, oid) in &self.vector {
            field(&mut hasher, name.as_str().as_bytes());
            field(&mut hasher, oid.as_str().as_bytes());
        }
        hasher.update(b"d");
        for name in &self.deletions {
            field(&mut hasher, name.as_str().as_bytes());
        }
        hasher.finalize().to_hex().to_string()
    }
}

/// One mirror's automatic run: the repository handle, the mirror row it
/// read and the directory whose lock is the mirror's push hold.
pub(crate) struct MirrorRunScope<'s, 'v> {
    pub(crate) wire: &'s GitWire<'v>,
    pub(crate) handle: &'s GitWireRepo,
    pub(crate) repo_id: EntityId,
    pub(crate) target: &'s OriginMirrorTarget,
    pub(crate) hold: &'s Path,
}

impl MirrorRunScope<'_, '_> {
    /// The destination the run sends to, as the mirror row names it.
    pub(super) fn destination(&self) -> OriginPublishDestination {
        OriginPublishDestination {
            url: self.target.url.clone(),
            user: self.target.user.clone(),
            secret_ref: self.target.secret_ref.clone(),
            target_generation: self.target.target_generation,
            audience: self.target.audience,
        }
    }
}

impl Vault {
    /// Reads, reviews and freezes one plan. Nothing goes out here. `None`
    /// when the mirror row moved since the run read it, or another plan is
    /// open: the next opportunity plans again.
    pub(super) fn freeze_mirror_plan(
        &self,
        scope: &MirrorRunScope<'_, '_>,
        selection: &MirrorSelection,
        requested_by: Option<EntityId>,
    ) -> Result<Option<MirrorPushPlan>> {
        let destination = scope.destination();
        let full_auto = scope.target.sync_strategy == OriginMirrorSyncStrategy::FullAuto;
        let names: Vec<GitRefName> = selection
            .vector
            .iter()
            .map(|(name, _)| name.clone())
            .chain(selection.deletions.iter().cloned())
            .collect();
        let observed = self.observe_mirror_refs(scope, &destination, &names);
        let seen = |name: &GitRefName| {
            observed
                .get(name)
                .cloned()
                .unwrap_or(MirrorObservedTip::Unknown {
                    cause: "not read".to_owned(),
                })
        };
        let (mut refs, mut initial, mut pages) = (Vec::new(), Vec::new(), Vec::new());
        let mut reviewed: Vec<GitOid> = Vec::new();
        for (name, new) in &selection.vector {
            let tip = seen(name);
            let covered = full_auto && self.mirror_holds_descendant(scope, new, &tip)?;
            let section = if covered {
                RefSection {
                    built: super::mirror_review::covered_section(name, new, &tip),
                    walked: None,
                }
            } else {
                self.review_whole_ref(scope.wire, scope.handle, name, new, &tip, &reviewed)?
            };
            reviewed.extend(section.walked);
            refs.push(MirrorPlanRef {
                ref_name: name.as_str().to_owned(),
                new: Some(new.as_str().to_owned()),
                observed: tip,
                review: Some(section.built.review),
                first_page: count(pages.len()),
                batch: None,
            });
            initial.push(if covered {
                MirrorRefOutcome::Covered
            } else {
                MirrorRefOutcome::Pending
            });
            pages.extend(section.built.pages);
        }
        for name in &selection.deletions {
            let tip = seen(name);
            initial.push(if tip == MirrorObservedTip::Absent {
                MirrorRefOutcome::ObservedApplied
            } else {
                MirrorRefOutcome::Pending
            });
            refs.push(MirrorPlanRef {
                ref_name: name.as_str().to_owned(),
                new: None,
                observed: tip,
                review: None,
                first_page: count(pages.len()),
                batch: None,
            });
        }
        let batches = cut_batches(&mut refs, &initial)?;
        let mut plan = MirrorPushPlan {
            plan_id: EntityId::now(),
            repo: scope.target.repo.clone(),
            repo_id: scope.repo_id,
            destination,
            strategy: scope.target.sync_strategy,
            strategy_revision: scope.target.strategy_revision,
            requested_by,
            refs,
            batches: u32::try_from(batches.len())
                .map_err(|_| Error::InvariantViolation("mirror plan batch count"))?,
            pending_checks: selection
                .pending
                .iter()
                .map(|(name, head, sent)| MirrorPendingHead {
                    ref_name: name.as_str().to_owned(),
                    head: head.as_str().to_owned(),
                    sent: sent.as_ref().map(|oid| oid.as_str().to_owned()),
                })
                .collect(),
            digest: String::new(),
            vector: selection.vector_digest(),
            pages: count(pages.len()),
            created_at: self.now_recorded_at(),
        };
        plan.digest = plan_digest(&plan);
        let mut txn = self.store.env.write_txn()?;
        if !self.mirror_fence_in_txn(&txn, &plan)?
            || !self.open_mirror_plan_in_txn(&mut txn, &plan, &pages, &batches)?
        {
            return Ok(None);
        }
        txn.commit()?;
        Ok(Some(plan))
    }
}

/// Cuts the refs left to send into batches, updates first and deletions
/// after, at most [`MIRROR_PUSH_REFSPECS`] a batch, in plan order.
fn cut_batches(
    refs: &mut [MirrorPlanRef],
    initial: &[MirrorRefOutcome],
) -> Result<Vec<MirrorBatchProgress>> {
    let mut batches = Vec::new();
    for deletion in [false, true] {
        let indexes: Vec<u32> = (0_u32..)
            .zip(refs.iter().zip(initial))
            .filter(|(_, (plan_ref, outcome))| {
                plan_ref.new.is_none() == deletion && **outcome == MirrorRefOutcome::Pending
            })
            .map(|(index, _)| index)
            .collect();
        for chunk in indexes.chunks(MIRROR_PUSH_REFSPECS) {
            let batch = u32::try_from(batches.len())
                .map_err(|_| Error::InvariantViolation("mirror plan batch count"))?;
            for index in chunk {
                if let Some(plan_ref) = refs.get_mut(*index as usize) {
                    plan_ref.batch = Some(batch);
                }
            }
            batches.push(MirrorBatchProgress {
                claim: MirrorBatchClaim::Pending,
                refs: chunk.to_vec(),
                outcomes: vec![MirrorRefOutcome::Pending; chunk.len()],
                detail: None,
            });
        }
    }
    Ok(batches)
}

/// One digest over a plan's destination (its audience included), strategy,
/// refs, observations, batches, sections and held heads.
fn plan_digest(plan: &MirrorPushPlan) -> String {
    let mut hasher = blake3::Hasher::new_derive_key(ORIGIN_MIRROR_PLAN_DIGEST_CONTEXT);
    hasher.update(plan.repo_id.as_bytes());
    let destination = &plan.destination;
    field(&mut hasher, destination.url.as_bytes());
    field(&mut hasher, destination.user.as_bytes());
    field(&mut hasher, destination.secret_ref.as_bytes());
    let generation = destination.target_generation.map(|id| id.to_hex());
    field(&mut hasher, generation.unwrap_or_default().as_bytes());
    field(
        &mut hasher,
        destination.audience.visibility.as_str().as_bytes(),
    );
    field(&mut hasher, destination.audience.role.as_str().as_bytes());
    field(&mut hasher, plan.strategy.as_str().as_bytes());
    hasher.update(&plan.strategy_revision.to_le_bytes());
    for plan_ref in &plan.refs {
        field(&mut hasher, plan_ref.ref_name.as_bytes());
        field(
            &mut hasher,
            plan_ref.new.as_deref().unwrap_or("").as_bytes(),
        );
        let (state, value) = match &plan_ref.observed {
            MirrorObservedTip::Absent => ("absent", ""),
            MirrorObservedTip::At { oid } => ("at", oid.as_str()),
            MirrorObservedTip::Unknown { cause } => ("unknown", cause.as_str()),
        };
        field(&mut hasher, state.as_bytes());
        field(&mut hasher, value.as_bytes());
        hasher.update(&plan_ref.batch.unwrap_or(u32::MAX).to_le_bytes());
        let section = plan_ref
            .review
            .as_ref()
            .map_or("", |review| review.digest.as_str());
        field(&mut hasher, section.as_bytes());
    }
    for held in &plan.pending_checks {
        field(&mut hasher, held.ref_name.as_bytes());
        field(&mut hasher, held.head.as_bytes());
        field(&mut hasher, held.sent.as_deref().unwrap_or("").as_bytes());
    }
    field(&mut hasher, plan.vector.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}
