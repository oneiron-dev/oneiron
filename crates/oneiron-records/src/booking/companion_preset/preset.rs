//! Moved from `crates/oneiron/src/booking/companion_preset/preset.rs` (lib split R2: record types below the lib).
//! `oneiron` re-exports each item at its old path.

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
