//! Moved from `crates/oneiron/src/outbound_chokepoint/fanout.rs` (lib split R1: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use serde::Deserialize;
use serde::Serialize;

/// The closed, surfaced pathology vocabulary. Every arm pauses for judgment
/// and carries the evidence a human needs to rule on it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FanoutPathology {
    ConsultCycle {
        peer_path: Vec<String>,
    },
    PerPeerRateSpike {
        peer_ref: String,
        projected_count: u32,
        spike_at: u32,
        window_secs: u64,
    },
}

impl FanoutPathology {
    /// The stable receipt/wire spelling of this arm, matching the serde tag.
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::ConsultCycle { .. } => "consult_cycle",
            Self::PerPeerRateSpike { .. } => "per_peer_rate_spike",
        }
    }
}

/// The receiptable choices a surfaced fan-out row offers. A pause row offers
/// the first three; a width-question row offers only `Ack` and
/// `AckAndRemember`, because there is nothing to keep paused or release.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanoutApprovalChoice {
    ApproveOnce,
    ApproveAndRememberBriefVerb,
    KeepPaused,
    Ack,
    AckAndRemember,
}

impl FanoutApprovalChoice {
    /// The stable per-choice action id carried on the surfaced row.
    pub const fn action_id(&self) -> &'static str {
        match self {
            Self::ApproveOnce => "fanout_approve_once",
            Self::ApproveAndRememberBriefVerb => "fanout_approve_and_remember_brief_verb",
            Self::KeepPaused => "fanout_keep_paused",
            Self::Ack => "fanout_check_ack",
            Self::AckAndRemember => "fanout_check_ack_and_remember",
        }
    }

    /// The receipt outcome this choice is recorded under.
    pub const fn outcome(&self) -> &'static str {
        match self {
            Self::ApproveOnce => "approved_once",
            Self::ApproveAndRememberBriefVerb => "grant_mint_intent",
            Self::KeepPaused => "kept_paused",
            Self::Ack => "acknowledged",
            Self::AckAndRemember => "acknowledged_and_remembered",
        }
    }
}
