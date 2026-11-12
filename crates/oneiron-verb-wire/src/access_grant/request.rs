//! Moved from `crates/oneiron/src/access_grant/request.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use oneiron_authority::authority::VerifiedSlip;
use oneiron_base::error::Error;
use oneiron_base::error::GateError;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use std::ops::Bound;

/// Terminal responses cannot be changed by a second responder.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessRequestStatus {
    Pending,
    Approved,
    Denied,
}
