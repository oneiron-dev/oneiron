//! Moved from `crates/oneiron/src/attempt_queue/cancel/types.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::attempt_cancel::AttemptCancelPressure;
pub use crate::store::attempt_cancel::AttemptCancelReceipt;
pub use crate::store::attempt_cancel::AttemptCancelReceiptKind;
pub use crate::store::attempt_cancel::AttemptCancellation;
pub use crate::store::attempt_cancel::AttemptLanding;
pub use crate::store::attempt_cancel::CancelMode;
pub use crate::store::attempt_cancel::CancelStanding;
pub use crate::store::attempt_cancel::ForceCancelGrounds;
pub use oneiron_wake_contract::store::attempt_cancel::AttemptResumePoint;
pub use oneiron_wake_contract::store::attempt_cancel::LandingTrigger;

/// Refused soft cancel requests after which repeated refusal is an observable
/// pathology rather than a legitimate "not yet".
///
/// Crossing it never changes the attempt's state: only the hard rung
/// (`AttemptQueue::force_cancel`)
/// can stop a worker that will not land, and this is the signal that says so.
pub const SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD: u32 = 3;

impl CancelStanding {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PeerAgent => "peer_agent",
            Self::Healer => "healer",
            Self::Automation => "automation",
            Self::Authority => "authority",
            Self::None => "none",
        }
    }

    /// Whether this standing may issue a soft `cancel.request`.
    #[must_use]
    pub const fn may_request(self) -> bool {
        !matches!(self, Self::None)
    }
}

impl ForceCancelGrounds {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::LeaseExpiry => "lease_expiry",
            Self::Criticality => "criticality",
            Self::ErasedPayload => "erased_payload",
        }
    }
}

impl CancelMode {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Landed => "landed",
            Self::Forced => "forced",
        }
    }
}

impl AttemptCancellation {
    /// A cancellation row is well-formed when its grounds match its mode: only
    /// a forced stop rests on grounds, and it always does.
    #[must_use]
    pub const fn is_well_formed(&self) -> bool {
        matches!(self.mode, CancelMode::Forced) == self.grounds.is_some()
    }
}

impl AttemptCancelReceiptKind {
    /// Stable wire/render token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoftRequested => "soft_requested",
            Self::LandingAccepted => "landing_accepted",
            Self::SoftRejected => "soft_rejected",
            Self::ResumePointRecorded => "resume_point_recorded",
            Self::ReserveSpent => "reserve_spent",
            Self::Landed => "landed",
            Self::ForceCancelled => "force_cancelled",
        }
    }

    /// True for the two rows that SETTLE an attempt. Exactly one of them may
    /// exist on a row, and it is always the last one. No receipt count
    /// refuses, so a long refusal history never leaves it without room.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Landed | Self::ForceCancelled)
    }

    /// True for the two rows that ANSWER one recorded soft request, and which
    /// therefore name it through [`AttemptCancelReceipt::request_sequence`].
    #[must_use]
    pub const fn answers_request(self) -> bool {
        matches!(self, Self::LandingAccepted | Self::SoftRejected)
    }
}

impl AttemptCancelPressure {
    /// True once refusals have crossed
    /// [`SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD`]. Observability only: it
    /// never terminates anything by itself.
    #[must_use]
    pub const fn is_pathological(&self) -> bool {
        self.rejections >= SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD
    }
}
