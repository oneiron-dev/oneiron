//! Moved from `crates/oneiron/src/outbound_consent/connector_call_sent.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::ops::Range;

/// One credential presentation a live connector exchange made: the custody
/// record its door released and that record's rotation generation, and
/// whether the released bytes read the same trimmed. Value-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SentGeneration {
    /// The custody record presented.
    pub custody: EntityId,
    /// The record's rotation generation its door released.
    pub generation: u32,
    /// The released bytes read the same trimmed. The known-value history
    /// keys the stored bytes, so only then does it cover the trimmed copy a
    /// sender presents and a connector may echo.
    pub trimmed: bool,
}

impl SentGeneration {
    /// Whether `other` presented the same value: the same record at the
    /// same generation.
    #[must_use]
    pub fn same_value(&self, other: &Self) -> bool {
        self.custody == other.custody && self.generation == other.generation
    }
}

/// What a live connector exchange presented, as its call's row keeps it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum SentGenerations {
    /// Not known: a row kept before presentations were, or a send whose
    /// door released a value without naming its record. Such an exchange
    /// is never resumed.
    #[default]
    Unknown,
    /// The exchange presented no credential.
    CredentialFree,
    /// Each distinct presentation it made, the first send's first.
    Presented(Vec<SentGeneration>),
}

impl SentGenerations {
    /// What one send presented: `None` when it presented nothing.
    #[must_use]
    pub fn of(sent: Option<SentGeneration>) -> Self {
        match sent {
            Some(sent) => Self::Presented(vec![sent]),
            None => Self::CredentialFree,
        }
    }

    /// These and `sent`, a resume's presentation, too. An unknown set stays
    /// unknown.
    #[must_use]
    pub fn with(self, sent: SentGeneration) -> Self {
        match self {
            Self::Unknown => Self::Unknown,
            Self::CredentialFree => Self::Presented(vec![sent]),
            Self::Presented(mut presented) => {
                if !presented.iter().any(|known| known.same_value(&sent)) {
                    presented.push(sent);
                }
                Self::Presented(presented)
            }
        }
    }
}
