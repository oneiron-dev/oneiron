//! Core half of `store::agent_refusal`: its store-layer items live in `oneiron_store::agent_refusal` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::agent_refusal::*;

#[cfg(doc)]
use crate::agent_def::VaultKind;
use serde::{Deserialize, Serialize};

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

impl RefusalLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Voice => "voice",
            Self::Veto => "veto",
            Self::Full => "full",
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "none" => Some(Self::None),
            "voice" => Some(Self::Voice),
            "veto" => Some(Self::Veto),
            "full" => Some(Self::Full),
            _ => None,
        }
    }
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
