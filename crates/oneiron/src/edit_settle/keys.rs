//! Pinned ledger keys and receipt fields.

/// Current settlement-record body schema version.
pub const SETTLEMENT_SCHEMA_VERSION: u64 = 2;

/// Pinned on-disk MessagePack key set for a [`SettlementRecord`](crate::edit_settle::SettlementRecord) body.
pub const SETTLEMENT_RECORD_KEYS: [&str; 17] = [
    "schema_version",
    "proposal_ref",
    "outcome",
    "settled_at",
    "actor_ref",
    "brief_ref",
    "before_version",
    "version",
    "content_hash",
    "manifest_ref",
    "manifest_ops",
    "anchors",
    "reason",
    "pptx_slide_creation_id_mints",
    "pptx_review_identities",
    "sheet_answers",
    "pptx_judgments",
];

/// Pinned on-disk MessagePack key set for one [`SettledAnchor`](crate::edit_settle::SettledAnchor) entry.
pub const SETTLED_ANCHOR_KEYS: [&str; 3] = ["thread_id", "locator", "drifted"];

/// Verb class a settle bundle-grant carries under the D6 brief×verb-class scope.
///
/// A settle-specific verb class keeps a future settle grant disjoint from
/// outbound-send grants (which carry `send`), so a send authorization can never
/// stand in for an artifact-write settle. See the module-level standing-grant
/// seam note.
pub const SETTLE_VERB_CLASS: &str = "artifact.settle";

pub(super) const KEY_SCHEMA_VERSION: &str = SETTLEMENT_RECORD_KEYS[0];

pub(super) const KEY_PROPOSAL_REF: &str = SETTLEMENT_RECORD_KEYS[1];

pub(super) const KEY_OUTCOME: &str = SETTLEMENT_RECORD_KEYS[2];

pub(super) const KEY_SETTLED_AT: &str = SETTLEMENT_RECORD_KEYS[3];

pub(super) const KEY_ACTOR_REF: &str = SETTLEMENT_RECORD_KEYS[4];

pub(super) const KEY_BRIEF_REF: &str = SETTLEMENT_RECORD_KEYS[5];

pub(super) const KEY_BEFORE_VERSION: &str = SETTLEMENT_RECORD_KEYS[6];

pub(super) const KEY_VERSION: &str = SETTLEMENT_RECORD_KEYS[7];

pub(super) const KEY_CONTENT_HASH: &str = SETTLEMENT_RECORD_KEYS[8];

pub(super) const KEY_MANIFEST_REF: &str = SETTLEMENT_RECORD_KEYS[9];

pub(super) const KEY_MANIFEST_OPS: &str = SETTLEMENT_RECORD_KEYS[10];

pub(super) const KEY_ANCHORS: &str = SETTLEMENT_RECORD_KEYS[11];

pub(super) const KEY_REASON: &str = SETTLEMENT_RECORD_KEYS[12];

pub(super) const KEY_SHEET_ANSWERS: &str = SETTLEMENT_RECORD_KEYS[15];

pub(super) const KEY_ANCHOR_THREAD_ID: &str = SETTLED_ANCHOR_KEYS[0];

pub(super) const KEY_ANCHOR_LOCATOR: &str = SETTLED_ANCHOR_KEYS[1];

pub(super) const KEY_ANCHOR_DRIFTED: &str = SETTLED_ANCHOR_KEYS[2];

pub(super) const BLOB_ARTIFACT_SETTLEMENT_KEY_PREFIX: &[u8] = b"blob_artifact:settlement:v1:";

pub(super) const OUTCOME_SELECTED: &str = "selected";

pub(super) const OUTCOME_DISCARDED: &str = "discarded";
pub(super) const OUTCOME_PROPOSED: &str = "proposed";

// Receipt field keys.

pub(super) const FIELD_ARTIFACT_REF: &str = "artifact_ref";

pub(super) const FIELD_PROPOSAL_REF: &str = "proposal_ref";

pub(super) const FIELD_RUN_REF: &str = "run_ref";

pub(super) const FIELD_BRIEF_REF: &str = "brief_ref";

pub(super) const FIELD_BEFORE_VERSION: &str = "before_version";

pub(super) const FIELD_VERSION: &str = "version";

pub(super) const FIELD_CONTENT_HASH: &str = "content_hash";

pub(super) const FIELD_MANIFEST_REF: &str = "manifest_ref";

pub(super) const FIELD_MANIFEST_OPS: &str = "manifest_ops";

pub(super) const FIELD_ANCHOR_MOVES: &str = "anchor_moves";

pub(super) const FIELD_ANCHOR_DRIFTS: &str = "anchor_drifts";

pub(super) const FIELD_SLIDE_JUDGMENTS: &str = "slide_judgments";

pub(super) const FIELD_REASON: &str = "reason";

pub(super) const KEY_PPTX_MINTS: &str = SETTLEMENT_RECORD_KEYS[13];

pub(super) const KEY_PPTX_REVIEW_IDENTITIES: &str = SETTLEMENT_RECORD_KEYS[14];
pub(super) const FIELD_SHEET_ANSWER_COUNT: &str = "sheet_answer_count";

pub(super) const FIELD_QUESTION_VERSION: &str = "question_version";

pub(super) const KEY_PPTX_JUDGMENTS: &str = SETTLEMENT_RECORD_KEYS[16];
