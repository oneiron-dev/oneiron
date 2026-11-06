//! Core half of `inbox::model`: its store-layer items live in `oneiron_store::inbox::model` and are
//! re-exported here; the items below stay in the engine.

pub use oneiron_store::inbox::model::*;

use crate::edit_distance::delta::AmendmentDelta;
use crate::error::Error;
use crate::side_table::{CodecError, RawValue};
use crate::store::PendingGateConsentRecord;
use crate::store::receipt_row::{ReceiptRecord, ReceiptView};
use serde::{Deserialize, Serialize};

/// Query for the inbox group projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxQuery {
    pub now: u64,
    /// Maximum number of groups returned.
    pub limit: usize,
    /// Resume after the page that answered this cursor (FIX 9873).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<InboxGroupCursor>,
}

impl InboxQuery {
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            now: crate::unix_seconds_now(),
            limit,
            after: None,
        }
    }

    #[must_use]
    pub const fn at(now: u64, limit: usize) -> Self {
        Self {
            now,
            limit,
            after: None,
        }
    }

    /// This query, resuming after `after` when it is set.
    #[must_use]
    pub const fn after(self, after: Option<InboxGroupCursor>) -> Self {
        Self { after, ..self }
    }
}

/// Where one browse page ended (FIX 9873): the tray position of the earliest
/// pending row of the last group it served, in the tray's own order
/// (proposal time, decision id, claim id). The next page serves the groups
/// whose earliest row lies after it. It resumes the traversal and nothing
/// else: it names no authority, expires nothing and counts nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InboxGroupCursor {
    created_at: u64,
    decision_id: [u8; 16],
    claim_id: [u8; 16],
}

impl InboxGroupCursor {
    /// The token's length: 8 + 16 + 16 bytes as lowercase hex.
    const TOKEN_LEN: usize = 80;

    /// The position of `record` in the tray's order.
    pub(crate) fn of(record: &PendingGateConsentRecord) -> Self {
        Self {
            created_at: record.created_at,
            decision_id: record.decision_id.as_bytes(),
            claim_id: record.claim_id,
        }
    }

    /// When the row at this position was proposed: its group's source time.
    #[must_use]
    pub(super) const fn created_at(&self) -> u64 {
        self.created_at
    }

    /// The cursor as a page's `next` carries it: 80 lowercase hex.
    #[must_use]
    pub fn to_token(&self) -> String {
        let mut bytes = Vec::with_capacity(Self::TOKEN_LEN / 2);
        bytes.extend_from_slice(&self.created_at.to_be_bytes());
        bytes.extend_from_slice(&self.decision_id);
        bytes.extend_from_slice(&self.claim_id);
        crate::entity_id::bytes_to_hex_lower(&bytes)
    }

    /// Reads a token [`Self::to_token`] wrote; `None` for anything else.
    #[must_use]
    pub fn parse(token: &str) -> Option<Self> {
        if token.len() != Self::TOKEN_LEN || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let bytes: Vec<u8> = (0..token.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&token[at..at + 2], 16).ok())
            .collect::<Option<_>>()?;
        Some(Self {
            created_at: u64::from_be_bytes(bytes[..8].try_into().ok()?),
            decision_id: bytes[8..24].try_into().ok()?,
            claim_id: bytes[24..40].try_into().ok()?,
        })
    }
}

/// One browse page (FIX 9873): complete visible groups in the tray's order,
/// and where the next page resumes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxGroupPage {
    pub groups: Vec<InboxGroup>,
    /// Pass back as the next request's `after`. Absent when no group lies
    /// past this page. A group the dial holds back whole is passed over, so
    /// a later page can come back with no visible group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<String>,
}

/// One dreamer-run group card over open pending proposals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxGroup {
    /// Group key: the run-tree ROOT attempt id (OF-193) when the run resolves in
    /// the attempt queue, otherwise the provenance-stamped run id. Every
    /// pending proposal of every run under that root is one of its members.
    pub group_key: String,
    /// The provenance-stamped dreamer run id of the group's earliest member.
    pub run_id: String,
    /// Dreamer-authored headline from the run brief's stated intent plus the
    /// run's item counts.
    pub headline: String,
    /// Earliest open member's created_at.
    pub created_at: u64,
    /// Members surfaced under the active dial.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<InboxGroupMember>,
    /// Open members the dial is currently holding out of the queue.
    pub held_member_count: usize,
    /// Pointer rows for members collapsed into an earlier group.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pointer_rows: Vec<InboxPointerRow>,
    /// Entity/theme sub-clusters, present only for many-item runs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sub_clusters: Vec<InboxSubCluster>,
    pub new_claim_count: usize,
    pub update_count: usize,
    pub conflict_count: usize,
}

/// One open proposal inside a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxGroupMember {
    pub claim_id: String,
    pub created_at: u64,
    pub age_secs: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hold_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exception_classes: Vec<InboxExceptionClass>,
    /// `new_claim` | `update` | `conflict` — the bundle-consent verb class.
    pub verb_class: String,
    /// Same-claim-hash duplicates from later runs collapsed onto this row.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duplicate_claim_ids: Vec<String>,
    pub receipt_view: ReceiptView,
}

/// Outcome of one bulk verb over a group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InboxBundleResolution {
    pub group_key: String,
    pub verb: InboxBulkVerb,
    /// Bundle reference carried by every receipt this resolution emitted.
    pub bundle_ref: String,
    /// The ONE bundle receipt carrying the run id (RS3 door).
    pub bundle_receipt: ReceiptRecord,
    /// Per-item resolution receipts (empty for review-each).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub item_receipts: Vec<ReceiptRecord>,
    /// Claim ids expanded for per-item review (review-each only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_items: Vec<String>,
}

/// Outcome of one approve-with-edit (ED-01, ONE-1757).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InboxAmendedApproval {
    pub claim_id: String,
    /// The `approved_amended` resolution receipt, Δ slot already filled.
    pub receipt: ReceiptRecord,
    /// The measured Δ. `None` means capture failed — the approval still
    /// landed, and the receipt carries the marker saying so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<AmendmentDelta>,
}

/// RS3 door result: the group behind a bundle receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxGroupReopen {
    pub group_key: String,
    /// Still-open remainder of the group, surfaced dial-independently.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub open_group: Option<InboxGroup>,
    /// Bundle + per-item receipts emitted for this group's bundles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_receipts: Vec<ReceiptRecord>,
}
