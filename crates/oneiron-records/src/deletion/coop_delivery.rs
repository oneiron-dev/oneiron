//! Moved from `crates/oneiron/src/deletion/coop_delivery.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::deletion::coop_delivery::types::CooperativeDeletionDisposition;
pub use crate::deletion::coop_delivery::types::CooperativeLocalRedaction;
pub use crate::deletion::coop_delivery::types::IncomingCooperativeDeletion;
use oneiron_base::error::Error;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeClaimValueRedaction;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeDeleteOperation;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeDeleteRecord;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeDeleteRecordState;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeDeletionRetention;
pub use oneiron_store::deletion::coop_delivery::types::CooperativeRestrictionLiftAttestation;
pub use oneiron_verb_wire::deletion::coop_delivery::types::CooperativeDeletionDispositionKind;
use serde::Deserialize;
use serde::Serialize;

pub fn invalid(reason: &str) -> Error {
    Error::InvalidConfig(format!("courtesy delete: {reason}"))
}

/// Parses `N` bytes of lowercase or uppercase hex.
pub fn parse_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.is_ascii() {
        return None;
    }
    let mut out = [0; N];
    for (slot, pair) in out.iter_mut().zip(value.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// The seven delivery states (BIZ-LEGAL-0004 A7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CooperativeDeletionDeliveryStatus {
    /// Staged; no try has started.
    Queued,
    /// A try started; retries keep this state.
    Sent,
    /// The peer's host answered 2xx: the ask is filed there.
    Delivered,
    /// The recipient's owner chose from the menu.
    Acknowledged,
    /// The recipient's owner declined.
    Declined,
    /// Retries ran out without an answer.
    Unreachable,
    /// The peer's host answered but did not file the ask; what it holds is unknown.
    Unknown,
}

impl CooperativeDeletionDeliveryStatus {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Sent => "sent",
            Self::Delivered => "delivered",
            Self::Acknowledged => "acknowledged",
            Self::Declined => "declined",
            Self::Unreachable => "unreachable",
            Self::Unknown => "unknown",
        }
    }

    /// The state `next` leaves this one in, or `None` when the move is not
    /// one the ledger makes: an answer is final, a try starts only from
    /// `queued` or `sent`, and a try's result lands only on `sent`.
    const fn advance(self, next: Self) -> Option<Self> {
        match (self, next) {
            (Self::Acknowledged | Self::Declined, _) | (_, Self::Queued) => None,
            (Self::Queued | Self::Sent, Self::Sent)
            | (Self::Sent, Self::Delivered | Self::Unknown | Self::Unreachable)
            | (_, Self::Acknowledged | Self::Declined) => Some(next),
            _ => None,
        }
    }
}

/// The sender's record of one ask to one recipient. It keeps request id,
/// connection id, a pseudonymous recipient id, status and timestamps, and
/// never the erased content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CooperativeDeletionNotice {
    /// The signed ask's nonce, hex.
    pub request_id: String,
    /// The pact the ask is about, hex.
    pub connection_id: String,
    /// [`cooperative_deletion_recipient_id`], hex.
    pub recipient_id: String,
    pub status: CooperativeDeletionDeliveryStatus,
    pub created_at: u64,
    pub updated_at: u64,
}
pub mod types;
