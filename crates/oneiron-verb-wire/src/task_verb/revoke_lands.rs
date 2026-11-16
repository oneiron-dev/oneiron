//! Moved from `crates/oneiron/src/task_verb/revoke_lands.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::connector_key::slate::SlatePackSource;
use serde::Deserialize;
use serde::Serialize;

/// What the owner reviewed, not a mutable pack name or source alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConnectorPackBasis {
    pub connector: String,
    pub source: SlatePackSource,
    pub key_ref: String,
    pub slate_ref: String,
    pub slate_revision: u64,
    pub manifest_hash: String,
    pub grant_hash: String,
    pub advisory_hash: String,
    pub protocol_revision: String,
}
