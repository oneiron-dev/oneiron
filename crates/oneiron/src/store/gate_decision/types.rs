//! Gate-decision ledger record shapes, id type, and version and bound consts.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entity_id::bytes_to_hex_lower;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GateDecisionId {
    pub(super) bytes: [u8; 16],
}

impl GateDecisionId {
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn now() -> Self {
        Self {
            bytes: Uuid::now_v7().into_bytes(),
        }
    }

    #[must_use]
    pub fn as_bytes(self) -> [u8; 16] {
        self.bytes
    }

    #[must_use]
    pub fn to_hex(self) -> String {
        bytes_to_hex_lower(&self.bytes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSystemNoticeAction {
    pub label: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSystemNoticeRecord {
    pub notice_type: String,
    pub channel: String,
    pub voice: String,
    pub audience: String,
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setting_change_offer: Option<GateSystemNoticeAction>,
    /// Which policy plane produced this notice — the vault owner's own policy,
    /// or a hosted service's legal policy. Absent for notices that are not
    /// policy verdicts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_plane: Option<String>,
    /// Version of the policy the notice was decided under. A hosted legal
    /// plane always sets it; the owner plane has no versioned document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// Where the reader can go to read the policy itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,
}

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
    /// Set when this row was redacted in place to its retention skeleton
    /// (version 1). Never set at append time; the erase coupling (ONE-1638)
    /// is the only writer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redacted_at: Option<u64>,
}

/// Outcome of one ERASE-A (ONE-1637) claim-index backfill run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GateClaimIndexBackfill {
    /// Pre-existing claim-bound ledger rows written into the index by this run.
    pub rows_indexed: u64,
    /// The durable flag was already set, so the run was a no-op.
    pub already_complete: bool,
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
}

/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub(crate) const GATE_DECISION_LEDGER_VERSION: u8 = 0;

/// Accepted DECODE version for an in-place-redacted row (ONE-1637/ONE-1638).
/// [`GATE_DECISION_LEDGER_VERSION`] (0) remains the only APPEND version, so the
/// ABI-pinned const above is unchanged and existing v0 bytes still round-trip.
pub(in crate::store) const GATE_DECISION_LEDGER_VERSION_REDACTED: u8 = 1;

pub(super) const PENDING_DELETION_GATE_DECISION_VERSION: u8 = 0;

pub(in crate::store) const GATE_DIFF_HANDLE_MAX_LEN: usize = 128;

pub(crate) const GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN: usize = 128;

/// Bounds on a notice's setting-change affordance. Named so the writers that
/// build a notice can hold themselves to the same numbers the ledger enforces,
/// instead of discovering them at append time.
pub(crate) const GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN: usize = 128;

pub(crate) const GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN: usize = 512;

pub(crate) const GATE_SYSTEM_NOTICE_BODY_MAX_LEN: usize = 1024;

pub(super) const GATE_SYSTEM_NOTICE_PLANE_MAX_LEN: usize = 64;

pub(crate) const GATE_SYSTEM_NOTICE_VERSION_MAX_LEN: usize = 64;

pub(crate) const GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN: usize = 512;
