//! Core half of `store::gate_decision::types`: its store-layer items live in `oneiron_store::gate_decision::types` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::gate_decision::types::*;

use super::context::GateDecisionContext;
use crate::entity_id::bytes_to_hex_lower;
use crate::side_table::SideKey;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateDecisionRecord {
    pub version: u8,
    pub decision_id: GateDecisionId,
    pub created_at: u64,
    pub outcome: String,
    pub reason_codes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub receipt_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_notices: Vec<GateSystemNoticeRecord>,
    pub actor_class: String,
    pub actor_ref: Option<String>,
    pub content_kind: String,
    pub policy_manifest_version: String,
    pub claim_id: Option<[u8; 16]>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_ref: Option<String>,
    pub diff_handle: Vec<u8>,
    pub read_frontier_hash: [u8; 32],
    /// What the decision was made about, the loop it came from and the
    /// ruled analysis of its input, captured by its original writer before
    /// its append (FIX 7499, 7500, 7801). Never consulted to decide a write.
    pub context: GateDecisionContext,
    /// Set when this row was redacted in place to its retention skeleton
    /// (version 1). Never set at append time; the erase coupling (ONE-1638)
    /// is the only writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_at: Option<u64>,
}

/// Private TXN1 recovery data for a deletion authority record. The target and
/// wire reason bind the sidecar to exactly one tombstone, so a remote update
/// cannot consume a same-request-id sidecar for a different deletion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(not(feature = "sync"), allow(dead_code))]
pub(super) struct PendingDeletionGateDecisionRecord {
    pub(super) version: u8,
    pub(super) target: [u8; 16],
    pub(super) tombstone_reason: u8,
    pub(super) decision: GateDecisionRecord,
    /// The original completed act, captured only by the local claimed-delete
    /// door. A remote tombstone cannot supply this binding.
    pub(super) authority_act: Option<[u8; 16]>,
}
