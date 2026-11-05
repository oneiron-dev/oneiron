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

use serde::{Deserialize, Serialize};

use super::types::AgentDefinition;
use crate::Vault;
use crate::error::Result;
use crate::federation::{SharedVaultCreation, SharedVaultPreset};

pub use crate::store::agent_refusal::{
    REFUSAL_DIAL_KEYS, RefusalDial, RefusalDomain, RefusalLevel,
};

impl RefusalLevel {
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
