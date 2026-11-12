//! Moved from `crates/oneiron/src/store/pack_hook_proposal.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// How a hook's body may spend model time (ARCH-0035 render classes;
/// ARCH-0080 §4 Its shape).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HookRenderClass {
    /// No model call: the body stays deterministic inside its budget.
    #[default]
    DeterministicEager,
    /// A fact hook that may call `ai.verdict`, paid from its pack's budget
    /// line.
    Generative,
}

impl HookRenderClass {
    pub const fn is_deterministic(&self) -> bool {
        matches!(self, Self::DeterministicEager)
    }
}

/// What an agent's hook asks beyond its own ceiling.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum HookWidening {
    /// Fail safe before the verb runs; only the owner marks a hook blocking.
    Blocking,
    /// A pre-hook's Skip of the verbs it selects.
    Skip,
    /// A pre-hook's Ask before the verbs it selects.
    Ask,
    /// A pre-hook's Rewrite of the verbs it selects.
    Rewrite,
}

/// Where a proposal stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PackHookProposalStatus {
    /// Waiting for the owner; the binding runs at the agent's ceiling.
    Proposed,
    /// The owner bound the hook as asked.
    Approved,
    /// The owner declined; the binding stays at the agent's ceiling.
    Discarded,
    /// The agent's later put no longer asks it, or stopped the hook.
    Withdrawn,
}
