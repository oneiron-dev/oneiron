//! Moved from `crates/oneiron/src/connect_delivery.rs` (lib split W3: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::authority::slip_vault::connect_lifecycle::ConnectWindow;
use oneiron_authority::federation::pact_scope::SelectorRange;
use serde::Deserialize;
use serde::Serialize;

/// One named sender world. Empty facet/band requests leave the pact ceiling alone.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectExportRequest {
    pub pact: String,
    pub window_key: String,
    pub world_ref: oneiron_contracts::entity_id::EntityId,
    #[serde(default)]
    pub facets: Vec<oneiron_contracts::entity_id::EntityId>,
    #[serde(default)]
    pub bands: Vec<SelectorRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectDelivery {
    pub body: ConnectWindow,
    pub signature: String,
    /// Unsigned export-preparation metadata; rejoin never uses it as authority.
    pub travel_receipt: Option<crate::share_travel::guest_window::GuestWindowTravelNote>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ConnectRejoinStatus {
    Imported,
    Deferred,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectRejoined {
    pub pact: String,
    pub epoch: u64,
    pub world_ref: oneiron_contracts::entity_id::EntityId,
    pub status: ConnectRejoinStatus,
    pub request: Option<String>,
}
