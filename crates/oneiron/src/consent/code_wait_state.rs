//! Consent-wait choices, settlement outcomes and bound call identities.

use crate::entity_id::EntityId;
use serde::{Deserialize, Serialize};

/// The three answers canon's confirm offers (DEC-0006): approve once (the
/// default), approve and stop asking, deny (CALLS: outcome names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeConsentChoice {
    ApproveOnce,
    ApproveAndStopAsking,
    Deny,
}

impl CodeConsentChoice {
    /// Every choice, in the order the wait's ask offers them.
    pub(crate) const ALL: [Self; 3] = [Self::ApproveOnce, Self::ApproveAndStopAsking, Self::Deny];

    /// The stable word, which is also the option id the wait's ask offers.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ApproveOnce => "approve_once",
            Self::ApproveAndStopAsking => "approve_and_stop_asking",
            Self::Deny => "deny",
        }
    }

    /// The choice an ask option id names, if any.
    #[must_use]
    pub fn from_option(option: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|choice| choice.as_str() == option)
    }

    /// Whether the choice lets the effect go to its own gate.
    pub(crate) const fn approves(self) -> bool {
        !matches!(self, Self::Deny)
    }
}

/// What one settled code consent wait came to (CALLS: outcome names). A
/// settlement is its own fact: it is not the answer, and it is not the
/// run's consumption of the reply, which 1b records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeConsentSettleOutcome {
    /// The effect ran and its connector acknowledged it.
    Delivered,
    /// Nothing ran, and nothing runs under this wait.
    Refused,
    /// The effect may have reached its connector; the ledger never sends it
    /// again, and it is never reported as delivered.
    DeliveryUnknown,
}

impl CodeConsentSettleOutcome {
    /// The stable word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delivered => "delivered",
            Self::Refused => "refused",
            Self::DeliveryUnknown => "delivery_unknown",
        }
    }

    /// The one-byte tag the settlement receipt carries.
    pub(crate) const fn tag(self) -> u8 {
        match self {
            Self::Delivered => 1,
            Self::Refused => 2,
            Self::DeliveryUnknown => 3,
        }
    }

    /// The outcome a settlement receipt's tag names, if any.
    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        [Self::Delivered, Self::Refused, Self::DeliveryUnknown]
            .into_iter()
            .find(|outcome| outcome.tag() == tag)
    }
}

/// Where one code consent wait stands, derived from the row's facts and
/// never stored on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CodeConsentWaitState {
    /// Minted with its held effect; its parked step has not sealed it, so no
    /// answer reaches it.
    Provisional,
    /// Sealed, with no answer.
    Waiting,
    /// Answered; the effect's own gate has not settled it.
    Settling,
    /// Settled: delivered, refused or of unknown delivery. The parked run
    /// has not taken the reply into its replay yet.
    Settled,
    /// The parked run took the settled reply into its replay, once (1b).
    Consumed,
}

/// Where one code-mode connector call sits in its durable run. The
/// dispatcher builds it from the executor's own bridge position and
/// carries it on the host-owned write origin; no guest field reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CodeConsentCallSite {
    pub(crate) wait_id: EntityId,
    pub(crate) run_id: EntityId,
    pub(crate) run_ref: String,
    pub(crate) step_start: u64,
    pub(crate) bridge_seq: u64,
    pub(crate) write_ordinal: u64,
    pub(crate) write_receipt_id: EntityId,
    /// BLAKE3 of the call's canonical identity (verb and sorted input).
    pub(crate) request_digest: [u8; 32],
}

/// The reason a wait settles with when its original caller's own credential
/// no longer stands. No answer revives it.
pub(crate) const CODE_WAIT_ORIGINAL_AUTHORITY_REFUSED: &str =
    "code_wait_original_authority_refused";
