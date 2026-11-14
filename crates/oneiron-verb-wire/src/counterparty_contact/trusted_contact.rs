//! Moved from `crates/oneiron/src/counterparty_contact/trusted_contact.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// Whether the engine asks the person before it reaches their contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustedContactDial {
    /// Ask first on either tier.
    AskFirst,
    /// Reach the contact at once on the imminent tier, and still ask first
    /// on the concern tier.
    JustCall,
}

/// How grave a `RouteToHelp` is. The tier belongs to this feature, not to the
/// gate: the owner names a row imminent, and every other row is a concern.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustedContactTier {
    Concern,
    Imminent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TrustedContactParty {
    Person,
    Contact,
}

/// Where the notice goes, on the existing outbound rails: `sender` is the
/// actor whose channel identity speaks, `channel` and `verb` a registered
/// outbound capability, and `target` the contact's address on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactReach {
    pub sender: EntityId,
    pub channel: String,
    pub verb: String,
    pub target: String,
}

/// The contact's consent, given with their word that they are an adult.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactAcceptance {
    pub at: u64,
    pub adult: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactRevocation {
    pub at: u64,
    pub by: TrustedContactParty,
}

/// One person's trusted contact. Naming it is the person's consent; the
/// contact's is [`Self::accepted`], given to exactly this [`Self::version`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContact {
    pub person: EntityId,
    pub contact: EntityId,
    pub reach: TrustedContactReach,
    pub dial: TrustedContactDial,
    /// Counts the times the person named this contact. Naming again changes
    /// what the contact agreed to, so it needs their consent again.
    pub version: u64,
    pub named_at: u64,
    pub accepted: Option<TrustedContactAcceptance>,
    pub revoked: Option<TrustedContactRevocation>,
}

impl TrustedContact {
    /// Both sides consent, the contact is an adult, and neither has revoked.
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.revoked.is_none() && self.accepted.is_some_and(|accepted| accepted.adult)
    }
}

/// "May I reach your trusted contact?", raised by a `RouteToHelp` the
/// person's dial or the row's tier says to ask about first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactAsk {
    pub ask: EntityId,
    pub person: EntityId,
    pub contact: EntityId,
    /// The relation version asked about; a yes to an older one sends nothing.
    pub version: u64,
    pub tier: TrustedContactTier,
    pub asked_at: u64,
    pub answer: Option<TrustedContactAnswer>,
    /// When the naming asked about was revoked or replaced before an answer.
    /// It closes the ask: answering it sends nothing, and says so.
    pub superseded: Option<u64>,
}

impl TrustedContactAsk {
    /// Neither answered nor superseded.
    #[must_use]
    pub fn is_open(&self) -> bool {
        self.answer.is_none() && self.superseded.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustedContactAnswer {
    pub yes: bool,
    pub at: u64,
    /// The yes staged a notice: the relation was still live as asked about.
    pub notified: bool,
}
