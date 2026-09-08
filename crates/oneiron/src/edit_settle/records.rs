//! Consent, outcome and settlement records.

use super::keys::{OUTCOME_DISCARDED, OUTCOME_SELECTED};
use crate::anchored_annotation::{Locator, ReanchorSummary};
use crate::blob_artifact::{BLOB_ARTIFACT_CONTENT_HASH_LEN, BlobArtifactVersion};
use crate::entity_id::EntityId;
use crate::receipt::ReceiptRecord;

// ---------------------------------------------------------------------------
// Consent / authorization
// ---------------------------------------------------------------------------

/// How a settle is authorized (OF-368 D6).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SettleConsent {
    /// The owner is settling the retained output directly (viewer select or
    /// discard). The owner action IS the consent — the fully implemented P1
    /// path. `brief_ref` optionally names the assigning brief so the settle
    /// receipt joins that brief's project view.
    OwnerConsent { brief_ref: Option<String> },
    /// Rely on a standing brief×verb-class bundle grant to settle without a
    /// per-op consent prompt (the D6 escalation). `brief_ref` names the brief
    /// the grant must cover. SEAM — see [`Vault::settle_standing_grant_authorizes`].
    StandingGrant { brief_ref: String },
}

impl SettleConsent {
    /// The assigning brief this settle rides, if any — recorded on the receipt.
    #[must_use]
    pub fn brief_ref(&self) -> Option<&str> {
        match self {
            Self::OwnerConsent { brief_ref } => brief_ref.as_deref(),
            Self::StandingGrant { brief_ref } => Some(brief_ref),
        }
    }
}

// ---------------------------------------------------------------------------
// Settlement record (the consume-once ledger + receipt substrate)
// ---------------------------------------------------------------------------

/// Which way a proposal was consumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleOutcomeKind {
    /// The proposal became a new blob-artifact version.
    Selected,
    /// The proposal was dropped.
    Discarded,
}

impl SettleOutcomeKind {
    /// The pinned on-disk / receipt outcome string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Selected => OUTCOME_SELECTED,
            Self::Discarded => OUTCOME_DISCARDED,
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            OUTCOME_SELECTED => Some(Self::Selected),
            OUTCOME_DISCARDED => Some(Self::Discarded),
            _ => None,
        }
    }
}

/// One anchor the select re-anchor sweep moved, captured at settle time
/// (record-not-replay): a remapped anchor carries its new locator on the new
/// version; a drifted anchor carries the origin locator it stayed pinned to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledAnchor {
    /// The annotation thread whose anchor moved.
    pub thread_id: EntityId,
    /// The locator the anchor resolved to after the settle.
    pub locator: Locator,
    /// Whether the anchor drifted (its region was destroyed) rather than remapped.
    pub drifted: bool,
}

/// The durable consume-once ledger entry for one settled proposal, and the
/// substrate the settle receipt projects from.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SettlementRecord {
    /// The agent run ref that produced the proposal — the consume-once key.
    pub proposal_ref: String,
    /// Whether the proposal was selected or discarded.
    pub outcome: SettleOutcomeKind,
    /// Settle time (engine clock).
    pub settled_at: u64,
    /// The settling actor's entity ref (hex), for the receipt.
    pub actor_ref: Option<String>,
    /// The assigning brief this settle rode, if any.
    pub brief_ref: Option<String>,
    /// The artifact head version the select was appended ONTO — the D6 receipt's
    /// before-version ref (select only; a discard commits no version).
    pub before_version: Option<u64>,
    /// The committed version (select only).
    pub version: Option<u64>,
    /// The committed version's content hash (select only).
    pub content_hash: Option<[u8; BLOB_ARTIFACT_CONTENT_HASH_LEN]>,
    /// Content hash of the edit-manifest bytes (select only) — the D6 manifest
    /// summary handle.
    pub manifest_ref: Option<[u8; 32]>,
    /// Number of ops in the manifest (0 for a discard).
    pub manifest_ops: u64,
    /// The anchor set that moved on select (empty for a discard).
    pub anchors: Vec<SettledAnchor>,
    /// Why the proposal was discarded (discard only).
    pub reason: Option<String>,
}

/// The tappable-door resolution of a select receipt: the committed
/// `artifact@version` plus the anchor set that moved (OF-368 D6).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SettleReceiptDoor {
    /// The artifact the select committed to.
    pub artifact_id: EntityId,
    /// The version the proposal became.
    pub version: u64,
    /// The anchors the re-anchor sweep moved.
    pub anchors: Vec<SettledAnchor>,
}

/// The result of a settle-select: the committed version, the re-anchor sweep
/// summary, and the select receipt.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SettleSelectOutcome {
    /// The version the proposal became.
    pub version: BlobArtifactVersion,
    /// The threads that remapped or drifted.
    pub reanchor: ReanchorSummary,
    /// The select receipt (OF-367 family).
    pub receipt: ReceiptRecord,
}

/// The result of a settle-discard: the discard receipt.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SettleDiscardOutcome {
    /// The discard receipt (OF-367 family).
    pub receipt: ReceiptRecord,
}
