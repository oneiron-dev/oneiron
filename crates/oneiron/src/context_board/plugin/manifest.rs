//! Versioned section-manifest schema, verb allowlist, and install traits.
use super::super::frame::BudgetPolicyRef;
use super::errors::PluginResult;
use super::install::PluginInstallTarget;
use crate::board_verb::BOARD_VERBS;
use crate::entity_id::EntityId;
use crate::skill::SkillRecord;
use crate::skill_hub::{HubPackage, HubRef};
use crate::task_verb::TASKS_VERBS;
use crate::vault::Vault;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Pinned schema version of [`SectionManifestEnvelope`]. Admission accepts this
/// exact version and nothing else — an unknown version fails closed rather than
/// being best-effort decoded.
pub const SECTION_MANIFEST_SCHEMA_VERSION: u16 = 1;

// ---------------------------------------------------------------------------
// §2 — versioned manifest schema
// ---------------------------------------------------------------------------
/// Versioned wrapper over the pinned manifest. `deny_unknown_fields` is the
/// schema's fail-closed edge: a pack cannot smuggle a field the engine will
/// silently ignore today and interpret tomorrow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionManifestEnvelope {
    pub schema_version: u16,
    pub manifest: SectionManifest,
}

/// The pinned section recipe. The four recipe components
/// (`state_family` · `verbs` · `authority_lane` · `budget_policy`) are typed
/// REFERENCES, never callbacks or prompt fragments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionManifest {
    pub section_id: SectionId,
    pub name: String,
    pub state_family: StateFamilyRef,
    pub verbs: Vec<SectionVerbRef>,
    pub authority_lane: AuthorityLaneRef,
    pub budget_policy: BudgetPolicyRef,
    pub provenance: SectionManifestProvenance,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SectionId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StateFamilyRef {
    pub family: String,
    pub version: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SectionVerbRef(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuthorityLaneRef(pub String);

/// Exact package identity the manifest claims to come from. Both validation
/// phases compare this against real bytes; neither trusts it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionManifestProvenance {
    pub pack_id: String,
    pub skill_id: String,
    pub skill_version: String,
    pub content_hash_hex: String,
}

// ---------------------------------------------------------------------------
// §2 — the closed verb chokepoint
// ---------------------------------------------------------------------------
/// The exact exported engine verb surface: `BOARD_VERBS ∪ TASKS_VERBS`.
///
/// Built from the exported constants at admission rather than from a caller
/// resolver — an injectable resolver could bless a string the engine does not
/// implement, which is precisely the hole this chokepoint closes. A manifest
/// may ADVERTISE an existing typed verb; ONE-1706 does not bind plugin rows to
/// execute one (PARK: the post-A2 verb-dispatch integration ticket owns that).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SectionVerbAllowlist(BTreeSet<SectionVerbRef>);

impl SectionVerbAllowlist {
    #[must_use]
    pub fn from_exported_verbs() -> Self {
        Self(
            BOARD_VERBS
                .iter()
                .chain(TASKS_VERBS.iter())
                .map(|verb| SectionVerbRef((*verb).to_owned()))
                .collect(),
        )
    }

    #[must_use]
    pub fn contains(&self, verb: &SectionVerbRef) -> bool {
        self.0.contains(verb)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Resolves the manifest's typed references against the live engine surface.
pub trait SectionBindingResolver {
    fn state_family_exists(&self, state_family: &StateFamilyRef) -> bool;
    fn authority_lane_exists(&self, authority: &AuthorityLaneRef) -> bool;
    fn budget_policy_exists(&self, budget: &BudgetPolicyRef) -> bool;
}

/// Read-only exact-byte source, consulted before consent and again before
/// admission. It never writes: proposal validation must be able to run against
/// an uninstalled package without importing a single byte.
pub trait PluginInstallSource {
    fn skill_record(&self, skill_ref: &EntityId) -> PluginResult<Option<SkillRecord>>;
    fn hub_package(&self, hub_ref: &HubRef) -> PluginResult<HubPackage>;
}

/// Post-consent executor over the EXISTING checked hub-import and
/// skill-admission doors. ONE-1706 consumes those doors; it does not
/// reimplement the lifecycle table or mint a second import path.
pub trait PluginInstallExecutor: PluginInstallSource {
    fn import_candidate_under_claim(
        &self,
        vault: &Vault,
        target: &PluginInstallTarget,
        approved_claim_id: &EntityId,
        now: u64,
    ) -> PluginResult<EntityId>;

    fn admit_candidate_under_claim(
        &self,
        vault: &Vault,
        skill_ref: &EntityId,
        approved_claim_id: &EntityId,
        now: u64,
    ) -> PluginResult<SkillRecord>;
}

/// Immutable lifecycle read used by every render and reachable-verb read.
/// This rebuild-on-read IS the registry's lifecycle subscription — it needs no
/// write hook in `skill.rs` / `skill_hub.rs`.
pub trait SkillLifecycleSource {
    fn skill_record(&self, skill_id: &str) -> PluginResult<Option<SkillRecord>>;
}
