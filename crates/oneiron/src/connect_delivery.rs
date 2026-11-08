//! Connect delivery and rejoin wire vocabulary.
use crate::authority::ConnectWindow;
use crate::federation::SelectorRange;
use serde::{Deserialize, Serialize};

/// One named sender world. Empty facet/band requests leave the pact ceiling alone.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectExportRequest {
    pub pact: String,
    pub window_key: String,
    pub world_ref: crate::EntityId,
    #[serde(default)]
    pub facets: Vec<crate::EntityId>,
    #[serde(default)]
    pub bands: Vec<SelectorRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectDelivery {
    pub body: ConnectWindow,
    pub signature: String,
    /// Unsigned export-preparation metadata; rejoin never uses it as authority.
    pub travel_receipt: Option<crate::share_travel::GuestWindowTravelNote>,
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
    pub world_ref: crate::EntityId,
    pub status: ConnectRejoinStatus,
    pub request: Option<String>,
}
