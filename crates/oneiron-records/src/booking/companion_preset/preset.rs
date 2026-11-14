//! Moved from `crates/oneiron/src/booking/companion_preset/preset.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::booking::config::EventTypeConfig;
use serde::Deserialize;
use serde::Serialize;

/// How a proposal reaches its participants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProposalCarrier {
    MessageLink,
}

/// How a proposal terminates. A soft confirmation is the companion saying "this
/// is the one" — distinct from a business hard commit, which this path has no
/// door onto.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompanionConfirmationMode {
    SoftViaCompanion,
}

/// The runtime preset: the pack-data row plus the caller-supplied synthetic
/// configuration it runs the shared solver against.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CompanionPresetRow {
    pub id: String,
    pub carrier: ProposalCarrier,
    pub confirmation: CompanionConfirmationMode,
    pub synthetic_event_type_config: EventTypeConfig,
    pub personal_hours: bool,
    pub generous_flex: bool,
    pub email_otp_enabled: bool,
    pub group_intersection: bool,
}
