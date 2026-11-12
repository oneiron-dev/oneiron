//! Moved from `crates/oneiron/src/share_travel/agent_pack_export.rs` (lib split W1: wire types below the lib).
//! `oneiron` re-exports each item at its old path.

use base64::Engine as _;
use oneiron_authority::claim_history_handoff::ClaimReadStatus;
use oneiron_authority::claim_history_handoff::ScopedRead;
use oneiron_authority::share_travel::BornWith;
use oneiron_authority::share_travel::TravelChoice;
use oneiron_authority::share_travel::TravelKind;
use oneiron_base::error::Error;
use oneiron_base::registry::ENTITY_TYPE_AGENT_DEF;
use oneiron_base::registry::ENTITY_TYPE_CLAIM;
use oneiron_base::registry::ENTITY_TYPE_SKILL;
use oneiron_base::registry::ENTITY_TYPE_WORLD;
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::memory::MemoryResult;
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_contracts::record_layout::EntityMetadataHeader;
use oneiron_store::batch::export::archive_types::ExportEntity;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::collections::BTreeSet;

/// Which agent to share, and the born-with text to send with it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AgentPackExportRequest {
    pub agent_ref: String,
    /// The born-with text to send with the pack; absent sends none (OF-491).
    #[serde(default)]
    pub travel: Option<TravelChoice>,
}
