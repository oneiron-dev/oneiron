//! The refusal dial (OF-533) an agent definition stores: one position from
//! none to full, and the agent's explicit setting per domain.

use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::agent_def::VaultKind;

/// One position on the dial, weakest to strongest.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum RefusalLevel {
    /// She proceeds silently; nothing is recorded.
    None,
    /// One objection with a reason, on the record, then she proceeds.
    Voice,
    /// She declines the act she objects to, with her reason.
    Veto,
    /// The far end: she refuses outright. Settable, never a default.
    Full,
}

/// An agent's explicit dial settings. A domain left unset takes the
/// vault-kind default ([`VaultKind::default_refusal`]); a set domain may sit
/// anywhere from `None` to `Full`. An empty dial is not a valid record:
/// omitting the dial is the one spelling of "every domain at its default".
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RefusalDial {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<RefusalLevel>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logistics: Option<RefusalLevel>,
}
