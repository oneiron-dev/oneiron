//! Moved from `crates/oneiron/src/federation/agent_grant/grantless.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Why `vault.agents.grants.from_slip` minted nothing.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AgentGrantFromSlipUnchangedReason {
    /// The slip is revoked or expired, or no longer stands on its ancestry,
    /// Grant, invitation or delegation.
    SlipNotLive,
    /// The slip names no class `agent` or no read verb, or its holder is no
    /// live named agent.
    NotEligible,
    /// A Grant row names the slip's holder, or a counted mint once did: the
    /// owner's Grants govern its reach.
    AlreadyGranted,
}
