//! Moved from `crates/oneiron/src/learning_setting_doors.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_base::error::Error;
use serde::Deserialize;
use serde::Serialize;

/// A seed (a prior the vault's fit starts from, with a weight in runs) or a
/// pin (the value, whatever the fit says).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LearningSettingMode {
    Seed,
    Pin,
}

/// Where a row applies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LearningSettingScope {
    Vault,
    Goal,
    Project,
    TaskType,
}

/// `vault.settings.learning`'s input: every spawn-choice row, or one
/// key's.
#[derive(Debug, Clone, Default, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningSettingsRequest {
    /// Only this spawn choice: `model`, `width`, `pattern` or `budget`.
    #[serde(default)]
    pub key: Option<String>,
}

/// `vault.settings.learning.clear`'s input: the row of one key, mode and
/// scope. Clearing an absent row succeeds.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LearningSettingClear {
    pub key: String,
    pub mode: LearningSettingMode,
    #[serde(default)]
    pub goal: Option<String>,
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub task_type: Option<String>,
}

pub fn bad(message: &'static str) -> Error {
    Error::InvalidClaimBody(message)
}
