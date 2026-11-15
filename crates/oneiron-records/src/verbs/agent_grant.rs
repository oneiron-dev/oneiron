//! Moved from `crates/oneiron/src/verbs/agent_grant.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::federation::engine_controls::EngineControlChange;
use crate::federation::system_agent_grant::narrowing::SystemFunction;
use oneiron_contracts::entity_id::EntityId;
pub use oneiron_verb_wire::verbs::agent_grant::AgentGrantFromSlipOutcome;
pub use oneiron_verb_wire::verbs::agent_grant::AgentGrantFromSlipRequest;
pub use oneiron_verb_wire::verbs::agent_grant::AgentGrantMintRequest;
pub use oneiron_verb_wire::verbs::agent_grant::AgentGrantMinted;
pub use oneiron_verb_wire::verbs::agent_grant::AgentGrantRevokeRequest;
pub use oneiron_verb_wire::verbs::agent_grant::AgentGrantRevoked;
pub use oneiron_verb_wire::verbs::agent_grant::AgentGrantView;
pub use oneiron_verb_wire::verbs::agent_grant::BaseAgentList;
pub use oneiron_verb_wire::verbs::agent_grant::BaseAgentPrincipal;
pub use oneiron_verb_wire::verbs::agent_grant::SystemAgentGrantNarrowRequest;
use serde::Deserialize;
use serde::Serialize;

/// What a narrowing did (untangle 6.3c; S6-4 amended).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SystemAgentGrantNarrowed {
    /// Nothing to narrow: the grant already holds no more than asked, or no
    /// grant stands.
    Unchanged,
    /// Nothing changed: the narrowing breaks `breaks`. Ask again with
    /// `confirm` to apply it.
    ConfirmRequired {
        warning: String,
        breaks: Vec<SystemFunction>,
        /// 64 hex.
        confirm: String,
    },
    /// Applied: `grant` is the narrower grant (32 hex), none when the grant
    /// was revoked whole; `breaks` is what the owner confirmed.
    Narrowed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<EntityId>,
        breaks: Vec<SystemFunction>,
    },
}

/// `vault.engine.defaults`'s answer row: one grant the engine stood by
/// default, by its grant id, with its receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineDefaultGrantEntry {
    /// The grant (32 hex).
    pub grant: EntityId,
    pub receipt: crate::federation::system_agent_grant::EngineDefaultGrant,
}

/// `vault.engine.controls.changes`'s answer row: one change made through
/// the engine-control door, by its receipt id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineControlChangeEntry {
    /// The receipt (32 hex).
    pub id: EntityId,
    pub change: EngineControlChange,
}
