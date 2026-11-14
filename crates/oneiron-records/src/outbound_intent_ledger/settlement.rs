//! Moved from `crates/oneiron/src/outbound_intent_ledger/settlement.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;
use std::fmt;

/// Why a provider refused a send it says to try again later (FIX 8818).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderWaitKind {
    /// A rate limit: the provider's HTTP 429.
    RateLimit,
    /// A spent quota, such as a monthly message allowance.
    Quota,
}

impl ProviderWaitKind {
    /// Stable receipt spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RateLimit => "rate_limit",
            Self::Quota => "quota",
        }
    }
}

/// A queued send's provider wait (FIX 8818): the send certainly did not go,
/// it stays queued, and no attempt goes before `not_before` (vault clock
/// seconds) when the provider named an edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProviderRetryDirective {
    pub kind: ProviderWaitKind,
    pub not_before: Option<u64>,
}

impl ProviderRetryDirective {
    /// The provider's edge, when it is still ahead of `now`.
    #[must_use]
    pub fn waits_at(&self, now: u64) -> Option<u64> {
        self.not_before.filter(|edge| *edge > now)
    }
}

/// Where a send's reserved budget stands (FIX 7964).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationStatus {
    /// Admitted and not settled: the send may still go, or may have gone.
    Reserved,
    /// The send was delivered: the reserved debit is its charge.
    Settled,
    /// The send certainly did not go: its debits are out. A still-pending
    /// retry restores them before transport.
    Released,
}

impl ReservationStatus {
    /// Stable receipt spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Settled => "settled",
            Self::Released => "released",
        }
    }
}
