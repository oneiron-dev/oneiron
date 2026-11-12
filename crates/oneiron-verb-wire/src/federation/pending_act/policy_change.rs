//! Moved from `crates/oneiron/src/federation/pending_act/policy_change.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

/// Where a proposed change stands. Only `pending` takes an answer.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SharedActPolicyChangeState {
    /// Waiting on the live editors named in `awaiting`.
    Pending,
    /// Every live editor approved it, and its row was written.
    Applied,
    /// A live editor answered no.
    Vetoed,
    /// The vault's rows moved after it was proposed, so it can never apply.
    Stale,
}
