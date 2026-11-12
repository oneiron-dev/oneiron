//! Moved from `crates/oneiron/src/connector_key/lifecycle/proxy.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::slate::SlateDataClass;
use crate::connector_key::slate::SlateDisposition;
use crate::connector_key::slate::SlateDraftRow;
use crate::connector_key::slate::SlateOwnerOverride;
use crate::connector_key::slate::SlateToolManifest;
use oneiron_base::error::Error;
use oneiron_base::error::Result;
use oneiron_contracts::entity_id::EntityId;
use oneiron_store::connector_key_status::ConnectorKeyStatus;
use oneiron_store::gate_decision::types::GateDecisionId;
use serde_json::json;
use std::collections::BTreeMap;

/// The connector the OpenAI proxy registers as.
pub const PROXY_CONNECTOR: &str = "openai_proxy";
