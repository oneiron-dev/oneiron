//! Gate-decision ledger record shapes, id type, and version and bound consts.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::side_table::key::SideKey;
use oneiron_contracts::entity_id::bytes_to_hex_lower;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GateDecisionId {
    pub bytes: [u8; 16],
}

impl SideKey for GateDecisionId {
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            bytes: bytes.try_into().ok()?,
        })
    }
}

impl GateDecisionId {
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GateSystemNoticeAction {
    pub label: String,
    pub target: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
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

impl GateSystemNoticeRecord {
    /// A receipt's `key:value` details (its handle, digests, references) as
    /// audit notices on `channel`, one per detail: receipt reasons hold only
    /// the gate's own reason grammar. A detail past the body bound is cut at
    /// a char boundary.
    pub fn receipt_details(channel: &str, details: Vec<String>) -> Vec<Self> {
        details
            .into_iter()
            .map(|mut body| {
                body.truncate(body.floor_char_boundary(GATE_SYSTEM_NOTICE_BODY_MAX_LEN));
                Self {
                    notice_type: "receipt_detail".to_owned(),
                    channel: channel.to_owned(),
                    voice: "system".to_owned(),
                    audience: "audit".to_owned(),
                    body,
                    row_ref: None,
                    setting_change_offer: None,
                    policy_plane: None,
                    policy_version: None,
                    docs_url: None,
                }
            })
            .collect()
    }
}

/// Outcome of one ERASE-A (ONE-1637) claim-index backfill run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GateClaimIndexBackfill {
    /// Pre-existing claim-bound ledger rows written into the index by this run.
    pub rows_indexed: u64,
    /// The durable flag was already set, so the run was a no-op.
    pub already_complete: bool,
}

/// Receipt-family ABI-pin rule: changing this requires a
/// [`STORAGE_ABI_VERSION`] bump.
pub const GATE_DECISION_LEDGER_VERSION: u8 = 0;

/// Accepted DECODE version for an in-place-redacted row (ONE-1637/ONE-1638).
/// [`GATE_DECISION_LEDGER_VERSION`] (0) remains the only APPEND version, so the
/// ABI-pinned const above is unchanged and existing v0 bytes still round-trip.
pub const GATE_DECISION_LEDGER_VERSION_REDACTED: u8 = 1;

pub const PENDING_DELETION_GATE_DECISION_VERSION: u8 = 1;

pub const GATE_DIFF_HANDLE_MAX_LEN: usize = 128;

pub const GATE_SYSTEM_NOTICE_ROW_REF_MAX_LEN: usize = 128;

/// Bounds on a notice's setting-change affordance. Named so the writers that
/// build a notice can hold themselves to the same numbers the ledger enforces,
/// instead of discovering them at append time.
pub const GATE_SYSTEM_NOTICE_ACTION_LABEL_MAX_LEN: usize = 128;

pub const GATE_SYSTEM_NOTICE_ACTION_TARGET_MAX_LEN: usize = 512;

pub const GATE_SYSTEM_NOTICE_BODY_MAX_LEN: usize = 1024;

pub const GATE_SYSTEM_NOTICE_PLANE_MAX_LEN: usize = 64;

pub const GATE_SYSTEM_NOTICE_VERSION_MAX_LEN: usize = 64;

pub const GATE_SYSTEM_NOTICE_DOCS_URL_MAX_LEN: usize = 512;
