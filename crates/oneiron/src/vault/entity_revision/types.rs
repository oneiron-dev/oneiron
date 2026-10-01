//! Exact read frontiers and idle refresh contracts for editable entity text.

use crate::{EntityId, error::Result};
use serde::{Deserialize, Serialize};

/// Opaque singular reference to one retained document frontier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RevisionRef(pub [u8; 16]);

/// A published view of an entity's revision state after a change.
///
/// `previous_revision` is the tracked frontier before the change. `revision`
/// is the new live frontier, or `None` when the entity no longer has one.
/// `indexed_revision` is the frontier currently published to retrieval, when
/// one is available; it may lag `revision` until idle publication completes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntityRevisionChange {
    /// Entity whose revision state changed.
    pub entity: EntityId,
    /// Live revision before the change, if the entity had a tracked revision.
    pub previous_revision: Option<RevisionRef>,
    /// Live revision after the change, or `None` if it was removed.
    pub revision: Option<RevisionRef>,
    /// Revision currently represented by the retrieval indexes, if available.
    pub indexed_revision: Option<RevisionRef>,
}

/// An idle transaction that successfully advanced an entity's indexed frontier.
///
/// The notification is delivered only after the index transaction commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexedPublication {
    /// Entity whose index was advanced.
    pub entity: EntityId,
    /// Indexed frontier before this transaction committed.
    pub previous_indexed: RevisionRef,
    /// Exact revision made visible to indexed reads by this transaction.
    pub indexed: RevisionRef,
}

impl RevisionRef {
    /// Stable lowercase wire form; not an entity identity.
    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
    /// Parses one exact 16-byte frontier reference.
    pub fn from_hex(value: &str) -> Result<Self> {
        if value.len() != 32 || !value.is_ascii() {
            return Err(crate::error::Error::InvalidKey);
        }
        let mut bytes = [0; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|_| crate::error::Error::InvalidKey)?;
        }
        Ok(Self(bytes))
    }
}

/// Entity body version. A missing pin fails; it never falls back to live.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadMode {
    #[default]
    Live,
    Indexed,
    Pinned(RevisionRef),
}

/// Exact version handed to the embedding adapter at idle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedRevisionInput {
    pub entity: EntityId,
    /// The record's type byte at this revision.
    pub entity_type: u8,
    pub source_revision_ref: RevisionRef,
    pub body: Vec<u8>,
    pub fields: Vec<(String, String)>,
}

impl IndexedRevisionInput {
    /// What the embedder embeds for this revision: a CLAIM by the rule the
    /// pending worker leases by, any other record as its text fields joined
    /// by newlines.
    ///
    /// Idle publication asks the embedder only when this is `Some`. `None` —
    /// a text of whitespace and control characters alone — publishes the
    /// revision with no vector and drops the one it had.
    pub fn payload(&self) -> Option<crate::embed::PendingEmbeddingPayload> {
        crate::embed::indexed_payload(self.entity_type, &self.body, &self.fields)
    }
}

/// Caller-owned embedding provider. It runs outside the LMDB transaction.
/// `InvalidConfig`, `DimensionMismatch` and `InvalidVector` reject only this
/// input. Other errors abort the pass; check provider-wide configuration before
/// starting a pass rather than returning it as an input refusal.
pub trait IndexedRevisionEmbedder {
    fn embed_revision(&self, input: &IndexedRevisionInput) -> Result<Vec<f32>>;
}

/// Refresh receipts name only revisions actually published into the index.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct IndexedRefreshReport {
    pub refreshed: Vec<(EntityId, RevisionRef)>,
    pub superseded: Vec<EntityId>,
    /// Unpublished entity/revision inputs and their typed refusal reasons.
    pub failed: Vec<(EntityId, RevisionRef, crate::error::ErrorKind)>,
}

/// Citation's four coordinates, plus the original quote for drift display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedCitation {
    pub entity: EntityId,
    pub short_ref: String,
    pub source_revision_ref: RevisionRef,
    pub field: String,
    pub start_cursor: Vec<u8>,
    pub end_cursor: Vec<u8>,
    pub quote_hash: [u8; 32],
    pub quote: String,
}

/// A citation never substitutes new text when its cursors drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedCitation {
    pub quote: String,
    pub drifted: bool,
}

impl PinnedCitation {
    /// A short-ref citation carries the exact revision, not just an 8-bit hash.
    pub fn reference(&self) -> String {
        format!("{}@{}", self.short_ref, self.source_revision_ref.to_hex())
    }
}
