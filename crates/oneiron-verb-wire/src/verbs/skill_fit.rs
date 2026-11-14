//! Moved from `crates/oneiron/src/verbs/skill_fit.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The owner's skill-fit choice on the wire: the existing rule fit or the
/// owner-asked fit. A wire-only projection of
/// `SkillFitSetting`, never a second store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SkillFitChoice {
    RuleFit,
    OwnerAsked,
}

/// `vault.skills.fit.set`'s input: the fit ordinary installs run.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SkillFitSetRequest {
    pub setting: SkillFitChoice,
}
