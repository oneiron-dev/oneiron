//! Moved from `crates/oneiron/src/context_board/plugin/manifest.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::context_board::frame::BudgetPolicyRef;
use serde::Deserialize;
use serde::Serialize;

// ---------------------------------------------------------------------------
// §2 — versioned manifest schema
// ---------------------------------------------------------------------------
/// Versioned wrapper over the pinned manifest. `deny_unknown_fields` is the
/// schema's fail-closed edge: a pack cannot smuggle a field the engine will
/// silently ignore today and interpret tomorrow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SectionManifestEnvelope {
    pub schema_version: u16,
    pub manifest: SectionManifest,
}

/// The pinned section recipe. The four recipe components
/// (`state_family` · `verbs` · `authority_lane` · `budget_policy`) are typed
/// REFERENCES, never callbacks or prompt fragments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct SectionId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StateFamilyRef {
    pub family: String,
    pub version: u16,
}

#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
pub struct SectionVerbRef(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct AuthorityLaneRef(pub String);

/// Exact package identity the manifest claims to come from. Both validation
/// phases compare this against real bytes; neither trusts it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SectionManifestProvenance {
    pub pack_id: String,
    pub skill_id: String,
    pub skill_version: String,
    pub content_hash_hex: String,
}
