//! Moved from `crates/oneiron/src/federation/agent_grant.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::federation::agent_grant::grantless::AgentGrantFromSlipUnchangedReason;
use std::collections::BTreeSet;

/// The one-tap revoke command every agent grant carries.
pub const AGENT_GRANT_REVOKE_COMMAND: &str = "vault.agents.grants.revoke";
