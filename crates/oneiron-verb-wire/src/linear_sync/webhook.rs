//! Moved from `crates/oneiron/src/linear_sync/webhook.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::linear_sync::mirror_event::EventDirection;
use crate::linear_sync::mirror_event::LinearMirrorEvent;
use crate::linear_sync::model::LinearFieldConflict;
use crate::linear_sync::model::LinearIssueRef;
use oneiron_base::error::Error;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::entity_id::bytes_to_hex_lower;
use serde::Deserialize;
use serde::Serialize;

/// The provider's actor of one webhook: evidence, never a vault actor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LinearExternalActor {
    /// The provider's actor id.
    pub id: String,
    /// The provider's actor type (`user`, `integration`, ...).
    pub kind: String,
    /// The provider's display name, when it sent one.
    pub name: Option<String>,
}
