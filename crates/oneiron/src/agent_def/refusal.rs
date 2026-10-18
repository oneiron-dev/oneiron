//! The refusal dial (OF-533): an agent's own disposition to object to, or
//! decline, what she is asked to do, set per domain.
//!
//! Owner ruling 2026-09-23: each agent carries a dial from none to full; both
//! ends are settable and it is never a wall. A work vault's default is voice
//! only: one objection with a reason, on the record, then she does it. A
//! personal vault's default is a veto on the bond and voice on logistics. The
//! two ends (`None`, `Full`) are reached only by an explicit setting, never by
//! a default.
//!
//! This is the agent's own disposition, stored on her AGENT_DEF. It is not a
//! boundary state held against a counterpart: nothing here is keyed by
//! relationship, counts offences, or escalates. It grants nothing either: a
//! decline stops her own act, never another agent's, a person's, or a policy
//! hold.

use rmpv::Value;
use serde::{Deserialize, Serialize};

use super::types::AgentDefinition;
use crate::Vault;
use crate::error::{ArtifactError, Error, Result};
use crate::federation::{SharedVaultCreation, SharedVaultPreset};

/// The pinned sub-map keys for a [`RefusalDial`], in encode order. Each is
/// the wire string of its [`RefusalDomain`].
pub const REFUSAL_DIAL_KEYS: [&str; 2] = ["bond", "logistics"];

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

    /// The one evaluator: what an agent's tagged self-refusal becomes at this
    /// level. Only an explicit self-refusal is evaluated; inability, a
    /// provider's refusal and an owner's "no" never reach here.
    #[must_use]
    pub const fn outcome(self) -> RefusalOutcome {
        match self {
            Self::None => RefusalOutcome::Proceed,
            Self::Voice => RefusalOutcome::Object,
            Self::Veto | Self::Full => RefusalOutcome::Decline,
        }
    }
}

/// What a refusal concerns. The agent names it when she refuses, and her dial
/// may sit differently for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalDomain {
    /// The bond itself: what she is asked to be, or to do to it.
    Bond,
    /// The mechanics of the work: arrangements, errands, scheduling.
    Logistics,
}

impl RefusalDomain {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Bond => REFUSAL_DIAL_KEYS[0],
            Self::Logistics => REFUSAL_DIAL_KEYS[1],
        }
    }

    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "bond" => Some(Self::Bond),
            "logistics" => Some(Self::Logistics),
            _ => None,
        }
    }
}

/// What the dial makes of one tagged self-refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RefusalOutcome {
    /// Proceed; nothing is recorded.
    Proceed,
    /// Record her one objection with its reason, then proceed.
    Object,
    /// Decline the act, with her reason.
    Decline,
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

/// Which defaults an unset dial takes. This is the vault's existing
/// personal-versus-shared split, read from its shared-vault creation row the
/// way the shipped shared-act policies choose their `personal` or `shared`
/// rows (`federation/pending_act.rs`, `shipped_rows`) and the same-bytes
/// erase hold decides it stands in a shared vault (`memory/entity_erase.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultKind {
    /// A shared vault under any preset but `Personal`.
    Work,
    /// A person's own vault: no shared-vault creation row, or the `Personal`
    /// preset.
    Personal,
}

impl VaultKind {
    #[must_use]
    pub fn of(creation: Option<&SharedVaultCreation>) -> Self {
        match creation {
            Some(creation) if creation.preset != Some(SharedVaultPreset::Personal) => Self::Work,
            _ => Self::Personal,
        }
    }

    /// The level a domain takes when the agent's dial leaves it unset. Never
    /// `None` or `Full`: both ends are settable, neither is a default.
    #[must_use]
    pub const fn default_refusal(self, domain: RefusalDomain) -> RefusalLevel {
        match (self, domain) {
            (Self::Personal, RefusalDomain::Bond) => RefusalLevel::Veto,
            (Self::Personal, RefusalDomain::Logistics) | (Self::Work, _) => RefusalLevel::Voice,
        }
    }
}

/// The one resolver: where `def`'s dial sits for `domain` in a vault of
/// `vault_kind`. An explicit setting wins; an unset domain, or no dial at
/// all, takes the vault-kind default.
#[must_use]
pub fn resolve_refusal(
    def: &AgentDefinition,
    vault_kind: VaultKind,
    domain: RefusalDomain,
) -> RefusalLevel {
    def.refusal
        .and_then(|dial| dial.get(domain))
        .unwrap_or_else(|| vault_kind.default_refusal(domain))
}

impl Vault {
    /// This vault's kind, for [`resolve_refusal`].
    pub fn vault_kind(&self) -> Result<VaultKind> {
        Ok(VaultKind::of(self.shared_vault_creation()?.as_ref()))
    }

    pub(crate) fn vault_kind_in_txn(&self, txn: &heed::RoTxn<'_>) -> Result<VaultKind> {
        Ok(VaultKind::of(
            self.shared_vault_creation_in_txn(txn)?.as_ref(),
        ))
    }
}

/// Encodes a [`RefusalDial`] sub-map: the [`REFUSAL_DIAL_KEYS`] in pinned
/// order, each unset domain elided.
pub(super) fn encode_refusal_dial(dial: RefusalDial) -> Value {
    let entries = [
        (RefusalDomain::Bond, dial.bond),
        (RefusalDomain::Logistics, dial.logistics),
    ]
    .into_iter()
    .filter_map(|(domain, level)| {
        level.map(|level| (Value::from(domain.as_str()), Value::from(level.as_str())))
    })
    .collect();
    Value::Map(entries)
}

/// Strict [`RefusalDial`] decode: a map over [`REFUSAL_DIAL_KEYS`] with no
/// unknown or duplicate key and at least one domain set.
pub(super) fn decode_refusal_dial(value: &Value) -> Result<RefusalDial> {
    let Value::Map(entries) = value else {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "refusal must be a MessagePack map",
        )));
    };
    let mut dial = RefusalDial::new();
    for (key, level) in entries {
        let domain = key
            .as_str()
            .and_then(RefusalDomain::parse)
            .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "refusal keys must be one of bond|logistics",
            )))?;
        if dial.get(domain).is_some() {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "duplicate refusal key",
            )));
        }
        let level = level
            .as_str()
            .and_then(RefusalLevel::parse)
            .ok_or(Error::Artifact(ArtifactError::InvalidAgentDefBody(
                "refusal levels must be one of none|voice|veto|full",
            )))?;
        dial = dial.with(domain, level);
    }
    validate_refusal_dial(dial)?;
    Ok(dial)
}

pub(super) fn validate_refusal_dial(dial: RefusalDial) -> Result<()> {
    if dial.bond.is_none() && dial.logistics.is_none() {
        return Err(Error::Artifact(ArtifactError::InvalidAgentDefBody(
            "refusal must set at least one domain; omit it for the vault defaults",
        )));
    }
    Ok(())
}
