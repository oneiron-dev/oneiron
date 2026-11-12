//! The refusal dial (OF-533) an agent definition stores: one position from
//! none to full, and the agent's explicit setting per domain.

use serde::{Deserialize, Serialize};

#[cfg(doc)]
use crate::agent_def::VaultKind;

#[doc(hidden)]
pub use oneiron_verb_wire::store::agent_refusal::{REFUSAL_DIAL_KEYS, RefusalDomain, RefusalLevel};

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

impl RefusalDial {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            bond: None,
            logistics: None,
        }
    }

    /// Sets one domain explicitly; either end of the dial is allowed.
    #[must_use]
    pub fn with(mut self, domain: RefusalDomain, level: RefusalLevel) -> Self {
        match domain {
            RefusalDomain::Bond => self.bond = Some(level),
            RefusalDomain::Logistics => self.logistics = Some(level),
        }
        self
    }

    /// The explicit setting for `domain`, if any.
    #[must_use]
    pub const fn get(&self, domain: RefusalDomain) -> Option<RefusalLevel> {
        match domain {
            RefusalDomain::Bond => self.bond,
            RefusalDomain::Logistics => self.logistics,
        }
    }
}
