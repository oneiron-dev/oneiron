//! Moved from `crates/oneiron/src/verbs/legal_hold.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::deletion::legal_hold::types::LegalHoldFutureMessages;
use crate::deletion::legal_hold::types::LegalHoldTarget;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;

/// `vault.legal_holds.place`'s input: what the owner's customer hold names,
/// an optional opaque matter reference, and the future messages it names.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldPlaceRequest {
    /// Each `{"record": "<hex>"}`, `{"gate_partition": "<hex>"}` (a claim's
    /// gate-decision key partition), or `{"gate_partition": null}` (the
    /// claim-free partition).
    pub targets: Vec<LegalHoldTarget>,
    /// An opaque id, never free text: 1 to 128 of A-Z a-z 0-9 . _ : - /.
    #[serde(default)]
    pub matter_ref: Option<String>,
    /// The future messages the hold names: each matching new MESSAGE joins
    /// its copy until `until` or the lift (Ruling
    /// L10-21-OWNER-FUTURE-MESSAGES = A, ARCH-0038 :321). None captures
    /// nothing new.
    #[serde(default)]
    pub future_messages: Option<LegalHoldFutureMessages>,
}

/// `vault.legal_holds.widen`'s input: more targets for one of the owner's
/// standing customer holds. A hold never narrows; `lift` ends it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegalHoldWidenRequest {
    pub hold_id: EntityId,
    /// As [`LegalHoldPlaceRequest::targets`].
    pub targets: Vec<LegalHoldTarget>,
}
