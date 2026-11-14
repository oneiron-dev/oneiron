pub use crate::federation::agent_grant::grantless::AgentGrantFromSlipUnchangedReason;
use std::collections::BTreeSet;

pub mod grantless;

/// The one-tap revoke command every agent grant carries.
pub const AGENT_GRANT_REVOKE_COMMAND: &str = "vault.agents.grants.revoke";
