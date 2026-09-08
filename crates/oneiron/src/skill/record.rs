//! SKILL record types with pinned wire keys and size bounds.

use rmpv::Value;

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::entity_id::EntityId;

use super::identity::SkillContentHash;
use super::lifecycle::{SkillGovernanceTier, SkillLifecycle};

pub const SKILL_RECORD_BODY_KEYS: [&str; 14] = [
    "skillId",
    "desc",
    "version",
    "approvalStatus",
    "lifecycleStatus",
    "source",
    "confidence",
    "generated",
    "humanAuthored",
    "dependencies",
    "provenance",
    "contentHash",
    "forkedFrom",
    // ONE-1448 mints this key camelCase like every other one in the set. The
    // blueprint wrote it `governance_tier`; the registry's spelling wins,
    // because the wire is the registry.
    "governanceTier",
];

pub const SKILL_DEPENDENCY_KEYS: [&str; 2] = ["skillId", "minVersion"];

pub const SKILL_ID_MAX_BYTES: usize = 256;

pub const SKILL_VERSION_MAX_BYTES: usize = 128;

pub const SKILL_DESC_MAX_BYTES: usize = 4096;

pub const SKILL_MAX_DEPENDENCIES: usize = 64;

pub(super) const KEY_SKILL_ID: &str = SKILL_RECORD_BODY_KEYS[0];

pub(super) const KEY_DESC: &str = SKILL_RECORD_BODY_KEYS[1];

pub(super) const KEY_VERSION: &str = SKILL_RECORD_BODY_KEYS[2];

pub(super) const KEY_APPROVAL_STATUS: &str = SKILL_RECORD_BODY_KEYS[3];

pub(super) const KEY_LIFECYCLE_STATUS: &str = SKILL_RECORD_BODY_KEYS[4];

pub(super) const KEY_SOURCE: &str = SKILL_RECORD_BODY_KEYS[5];

pub(super) const KEY_CONFIDENCE: &str = SKILL_RECORD_BODY_KEYS[6];

pub(super) const KEY_GENERATED: &str = SKILL_RECORD_BODY_KEYS[7];

pub(super) const KEY_HUMAN_AUTHORED: &str = SKILL_RECORD_BODY_KEYS[8];

pub(super) const KEY_DEPENDENCIES: &str = SKILL_RECORD_BODY_KEYS[9];

pub(super) const KEY_PROVENANCE: &str = SKILL_RECORD_BODY_KEYS[10];

pub(super) const KEY_CONTENT_HASH: &str = SKILL_RECORD_BODY_KEYS[11];

pub(super) const KEY_FORKED_FROM: &str = SKILL_RECORD_BODY_KEYS[12];

pub(super) const KEY_GOVERNANCE_TIER: &str = SKILL_RECORD_BODY_KEYS[13];

pub(super) const KEY_DEP_SKILL_ID: &str = SKILL_DEPENDENCY_KEYS[0];

pub(super) const KEY_DEP_MIN_VERSION: &str = SKILL_DEPENDENCY_KEYS[1];

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SkillDependency {
    pub skill_id: String,
    pub min_version: Option<String>,
}

impl SkillDependency {
    #[must_use]
    pub fn new(skill_id: impl Into<String>) -> Self {
        Self {
            skill_id: skill_id.into(),
            min_version: None,
        }
    }

    #[must_use]
    pub fn with_min_version(skill_id: impl Into<String>, min_version: impl Into<String>) -> Self {
        Self {
            skill_id: skill_id.into(),
            min_version: Some(min_version.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct SkillRecord {
    pub skill_id: String,
    pub desc: String,
    pub version: String,
    pub approval_status: ClaimApprovalStatus,
    pub lifecycle_status: SkillLifecycle,
    pub source: ClaimSource,
    /// DEMOTED CACHE (ARCH-0053 §5, ONE-1738): a materialization of the
    /// `skill.reliability` claim's Beta posterior mean, not a fact of its own.
    /// Claims are truth — the authoritative value is the claim on this SKILL
    /// entity, and [`crate::skill_reliability::rebuild_skill_confidence_cache`]
    /// recomputes this field from it (CID-7's demotion pattern).
    ///
    /// Consequences that are load-bearing rather than incidental:
    /// - selection reads the CLAIM
    ///   ([`crate::skill_reliability::skill_selection_score`]), never this
    ///   field, so a clobbered cache cannot change which skills load;
    /// - moving it mints no content revision (see `skill_content_changed`), so
    ///   a cache refresh needs no `version` bump and does not trip the
    ///   imported-content fork law.
    ///
    /// The wire key stays `confidence` and the field stays `f32`: the demotion
    /// is about AUTHORITY, and renaming it would have been an ABI break for no
    /// semantic gain.
    pub confidence: f32,
    pub generated: bool,
    pub human_authored: bool,
    pub dependencies: Vec<SkillDependency>,
    pub provenance: Value,
    /// Canonical identity layer: SHA-256 over the canonicalized file tree
    /// ([`canonical_skill_tree_hash`]). `None` when the identity has not
    /// been computed yet (legacy rows, records without a materialized
    /// tree). Hub refs are NOT here — they are the separate mutable
    /// alias/provenance layer (provenance rows; structured `hub_ref`
    /// shapes land with the SKILL_HUB entity, ONE-1736).
    pub content_hash: Option<SkillContentHash>,
    /// Fork lineage (one fork law, shared with the ordinary AGENT_DEF row
    /// fork / ONE-1444): the parent SKILL entity this record was forked from.
    /// Immutable after birth; the fork door also writes the
    /// `DerivedFrom` lineage edge.
    pub forked_from: Option<EntityId>,
    /// Governance tier (ONE-1448): the axis that decides whether the
    /// automated edit loop may target this skill at all. `None` is an
    /// ABSENT MARK, not `standard` — see [`SkillGovernanceTier`].
    ///
    /// Owner-settable through the ordinary update door: marking a tier is a
    /// STATE flip, not a content revision (see `skill_content_changed`), so
    /// it needs no `version` bump and lands on an imported skill without
    /// tripping the fork law. That is what makes "the owner can mark tiers"
    /// true for the imported packs most in need of marking.
    pub governance_tier: Option<SkillGovernanceTier>,
}

impl SkillRecord {
    #[expect(
        clippy::too_many_arguments,
        reason = "constructor mirrors the pinned SKILL record fields"
    )]
    #[must_use]
    pub fn new(
        skill_id: impl Into<String>,
        desc: impl Into<String>,
        version: impl Into<String>,
        approval_status: ClaimApprovalStatus,
        lifecycle_status: SkillLifecycle,
        source: ClaimSource,
        confidence: f32,
        generated: bool,
        human_authored: bool,
        dependencies: Vec<SkillDependency>,
        provenance: Value,
    ) -> Self {
        Self {
            skill_id: skill_id.into(),
            desc: desc.into(),
            version: version.into(),
            approval_status,
            lifecycle_status,
            source,
            confidence,
            generated,
            human_authored,
            dependencies,
            provenance,
            content_hash: None,
            forked_from: None,
            governance_tier: None,
        }
    }

    /// Sets the canonical content hash (identity layer).
    #[must_use]
    pub fn with_content_hash(mut self, content_hash: SkillContentHash) -> Self {
        self.content_hash = Some(content_hash);
        self
    }

    /// Marks the governance tier ([`SkillGovernanceTier`]).
    #[must_use]
    pub const fn with_governance_tier(mut self, tier: SkillGovernanceTier) -> Self {
        self.governance_tier = Some(tier);
        self
    }

    /// Sets the fork-lineage parent (normally stamped by
    /// [`Vault::fork_skill_record`], not by hand).
    #[must_use]
    pub fn with_forked_from(mut self, parent: EntityId) -> Self {
        self.forked_from = Some(parent);
        self
    }
}
