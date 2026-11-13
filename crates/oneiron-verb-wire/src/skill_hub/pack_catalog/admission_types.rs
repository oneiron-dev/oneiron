//! Moved from `crates/oneiron/src/skill_hub/pack_catalog/admission_types.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::skill_hub::pack_catalog::manifest::PackAdapter;

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PackRuntimeRecipe {
    pub adapter: super::PackAdapter,
    pub runtime_id: String,
    pub runtime_hash: String,
}

#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct PackPermissions {
    pub bundled_skills: Vec<BundledSkillPermissions>,
    pub widening_bundled_skills: Vec<BundledSkillPermissions>,
    pub grants: Vec<String>,
    pub wakes: Vec<String>,
    /// Each hook's capability set as tokens: phase, verbs, actors, scope,
    /// outcome kinds, budget and the blocking dial.
    pub hooks: Vec<String>,
    /// Each organ's ask and pinned builds as tokens (OF-575).
    pub organs: Vec<String>,
    pub section_verbs: Vec<String>,
    pub section_authorities: Vec<String>,
    /// Only added powers are the widening passed to the fit ladder: a
    /// hook's lower budget or narrower scope and an organ's lower ceiling
    /// are not added.
    pub widening_grants: Vec<String>,
    pub widening_wakes: Vec<String>,
    pub widening_hooks: Vec<String>,
    pub widening_organs: Vec<String>,
    pub widening_section_verbs: Vec<String>,
    pub widening_section_authorities: Vec<String>,
}

/// A skill's requested capability surface, keyed by the authored skill identity.
#[derive(
    Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct BundledSkillPermissions {
    pub skill_id: String,
    pub bins: Vec<String>,
    pub env: Vec<String>,
    pub mcp: Vec<String>,
    pub allowed_tools: Vec<String>,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PackInstallStatus {
    Active,
    Candidate,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PackCandidateReason {
    RulesHit,
    CodeAutoInstallOff,
    QualificationRequired,
    /// A hub source whose dependencies carry OSV advisories, or whose
    /// advisory query did not complete, waits for the owner.
    Advisories,
    /// A travelling AgentPack whose World scope names no single local world
    /// waits for the owner to pick one, or to create it (OF-491).
    NeedsWorld,
}
