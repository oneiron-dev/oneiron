//! Moved from `crates/oneiron/src/connector_key/credential_binding.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::slate::SlateCapability;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeSet;

/// One connector's open issuer transition, as the steady-state views
/// surface it: the issuers, when it was detected, and the catalog slate
/// rows it holds. Value-less: no witness or credential pointers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ConnectorIssuerHaltView {
    pub old_issuer: String,
    pub new_issuer: String,
    pub detected_at: u64,
    /// Catalog slate rows the halt holds, by tool name.
    pub dependent_rows: Vec<String>,
}
