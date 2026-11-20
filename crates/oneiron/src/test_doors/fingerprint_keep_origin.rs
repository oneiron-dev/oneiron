//! The origin publish and mirror digests, for the K-proof of PLAN-UC-04 stage 3.2
//! (`tests/fingerprint_keep_origin.rs`).

use crate::entity_id::EntityId;
use crate::git_wire::{GitOid, GitRefName, GitRefTag, GitReviewItem};
use crate::origin::mirror_strategy::OriginMirrorSyncStrategy;
use crate::origin::publish::{
    MirrorObservedTip, MirrorSelection, OriginPublishDestination, OriginPublishReview,
};
use oneiron_store::origin::publish::mirror_plan_types::MirrorPendingHead;

/// An exact publish's review digest: `commit`, `base`, each `reviewed` commit, then
/// each item in order.
#[must_use]
pub fn publish_review_digest(
    commit: &GitOid,
    base: Option<&GitOid>,
    reviewed: &[GitOid],
    items: &[GitReviewItem],
) -> String {
    crate::origin::publish::publish_review_digest_for_test(commit, base, reviewed, items)
}

/// One write into a mirror plan's section digest, after its start.
#[derive(Debug, Clone)]
pub enum MirrorSectionWrite {
    /// An annotated tag on the ref's way.
    Tag(GitRefTag),
    /// The tree or blob the ref ends at.
    Object { kind: String, object: GitOid },
    /// A path the ref's tree holds.
    Item(GitReviewItem),
    /// A walked commit's review digest.
    Walk(String),
}

/// A mirror plan's section digest for the ref `name` at `new` over `observed`,
/// after `writes`.
#[must_use]
pub fn mirror_section_digest(
    name: &GitRefName,
    new: &GitOid,
    observed: &MirrorObservedTip,
    writes: &[MirrorSectionWrite],
) -> String {
    crate::origin::publish::section_digest_for_test(name, new, observed, writes)
}

/// The digest of what a mirror selection sends.
#[must_use]
pub fn mirror_vector_digest(vector: &[(GitRefName, GitOid)], deletions: &[GitRefName]) -> String {
    MirrorSelection {
        vector: vector.to_vec(),
        deletions: deletions.to_vec(),
        pending: Vec::new(),
    }
    .vector_digest()
}

/// Every field of a frozen mirror plan its digest reads, under the plan's names.
#[derive(Debug, Clone)]
pub struct MirrorPlanFields {
    pub repo_id: EntityId,
    pub destination: OriginPublishDestination,
    pub strategy: OriginMirrorSyncStrategy,
    pub strategy_revision: u64,
    pub refs: Vec<MirrorPlanRefFields>,
    pub pending_checks: Vec<MirrorPendingHead>,
    pub vector: String,
}

/// Every field of a plan's ref its digest reads, under the ref's names.
#[derive(Debug, Clone)]
pub struct MirrorPlanRefFields {
    pub ref_name: String,
    pub new: Option<String>,
    pub observed: MirrorObservedTip,
    pub batch: Option<u32>,
    pub review: Option<OriginPublishReview>,
}

/// A frozen mirror plan's digest, the plan holding `fields`.
#[must_use]
pub fn mirror_plan_digest(fields: &MirrorPlanFields) -> String {
    crate::origin::publish::plan_digest_for_test(fields)
}
