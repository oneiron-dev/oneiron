//! Moved from `crates/oneiron/src/memory/channel_doors/lifecycle.rs` (lib split W2: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use crate::memory::channel_doors::*;
use oneiron_contracts::entity_id::EntityId;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentityRequest {
    pub identity_ref: EntityId,
    /// FIX 6424 part 3: on `rotate` and `route_inbound`, the `request_ref`
    /// an earlier receipt of this same request named, to retry exactly that
    /// request (one that completed answers its recorded receipt); omitted,
    /// the call is a request of its own (its host's invocation id, else a
    /// fresh ref). `get` and `fulfill` read none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChannelIdentityReleaseRequest {
    pub identity_ref: EntityId,
    /// The engine enforces the manifest's quarantine floor for self-held
    /// addresses. Delegated accounts are released, never quarantined.
    pub quarantine_until: u64,
    /// FIX 6424 part 3 (CALLS `FIX 6424 lifecycle retry token`): the
    /// `request_ref` an earlier receipt of this same request named, to retry
    /// exactly that request (one that completed answers its recorded
    /// receipt). Omitted, the call is a request of its own, keyed by its
    /// host's invocation id when it names one, else by a fresh ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_ref: Option<EntityId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChannelIdentityCustody {
    SelfHeld,
    Delegated,
}
