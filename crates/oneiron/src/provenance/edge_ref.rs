//! Pinned predicate, body-key vocabulary, EdgeRef addressing, and supersession status.

use crate::claim::{ClaimSubject, EDGE_REF_LEN as CLAIM_EDGE_REF_LEN};
use crate::edge::EdgeKind;
use crate::entity_id::{ENTITY_ID_LEN, EntityId};
use crate::error::{Error, Result};

/// The pinned predicate for edge-provenance Claims (contracts.ts
/// `edgeProvenanceClaim.predicate`). Lives in the reserved `edge.*`
/// namespace: only the engine's provenance path may write it (D17).
pub const PREDICATE_EDGE_PROVENANCE: &str = "edge.provenance";

/// Byte length of an encoded [`EdgeRef`]:
/// `(source_id 16 B, edge_kind u8, target_id 16 B)` = 33 B.
pub const EDGE_REF_LEN: usize = CLAIM_EDGE_REF_LEN;

/// Pinned ON-DISK MessagePack key set for the `edge.provenance` value record
/// (contracts.ts `edgeProvenanceClaim.fields` + the ratified ONE-1138
/// vocabulary bump). Order is canonical: the encoder emits present fields in
/// this order. Exactly these ten keys — required: `actor_entity_ref`,
/// `confidence`, `supersession_status`; optional: `source_revision_ref`,
/// `body_snapshot_ref`, `valid_from`, `valid_to`, `substrate_ref`,
/// `reasoning_effort`, `actor_class` (`actor_class` is required on NEW-shape
/// claims at the wrapper level — see `resolve_persisted_actor_class`).
///
/// The decoder is FAIL-CLOSED on unknown keys, so growing this set is a
/// sync-versioning event (old nodes reject new keys). ONE-1138 was pinned as
/// the LAST cheap bump: validator, negative-test matrix, and the docs pin
/// moved together, exactly once, before multi-device reality.
pub const EDGE_PROVENANCE_BODY_KEYS: [&str; 10] = [
    "actor_entity_ref",
    "source_revision_ref",
    "body_snapshot_ref",
    "confidence",
    "supersession_status",
    "valid_from",
    "valid_to",
    "substrate_ref",
    "reasoning_effort",
    "actor_class",
];

pub(crate) const KEY_ACTOR_ENTITY_REF: &str = EDGE_PROVENANCE_BODY_KEYS[0];

pub(super) const KEY_SOURCE_REVISION_REF: &str = EDGE_PROVENANCE_BODY_KEYS[1];

pub(super) const KEY_BODY_SNAPSHOT_REF: &str = EDGE_PROVENANCE_BODY_KEYS[2];

pub(crate) const KEY_CONFIDENCE: &str = EDGE_PROVENANCE_BODY_KEYS[3];

pub(super) const KEY_SUPERSESSION_STATUS: &str = EDGE_PROVENANCE_BODY_KEYS[4];

pub(super) const KEY_VALID_FROM: &str = EDGE_PROVENANCE_BODY_KEYS[5];

pub(crate) const KEY_VALID_TO: &str = EDGE_PROVENANCE_BODY_KEYS[6];

pub(super) const KEY_SUBSTRATE_REF: &str = EDGE_PROVENANCE_BODY_KEYS[7];

pub(super) const KEY_REASONING_EFFORT: &str = EDGE_PROVENANCE_BODY_KEYS[8];

pub(super) const KEY_ACTOR_CLASS: &str = EDGE_PROVENANCE_BODY_KEYS[9];

/// Maximum byte length of an inline `reasoning_effort` scalar. contracts.ts
/// pins the field as a small inline "scalar"; the engine encodes it as a
/// short MessagePack string (LLM-API convention values like "low" /
/// "medium" / "high" / "xhigh"), validated non-empty and at most this many
/// bytes. The exact scalar encoding is flagged for ratification
/// (OWNER-DECISION, ONE-1138 PR).
pub const REASONING_EFFORT_MAX_BYTES: usize = 32;

/// A 33-byte reference addressing one directed edge:
/// `(source_id 16 B, edge_kind u8, target_id 16 B)`.
///
/// The encoding is byte-identical to the LMDB `edges_out` key produced by
/// `Store::encode_edge_key(source, kind, target)` — the spec test pins the
/// alignment so the two layouts cannot drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EdgeRef {
    /// Edge source entity id (bytes 0..16).
    pub source: EntityId,
    /// Edge kind discriminant (byte 16).
    pub kind: EdgeKind,
    /// Edge target entity id (bytes 17..33).
    pub target: EntityId,
}

impl EdgeRef {
    /// Creates an edge reference from its three components.
    #[must_use]
    pub fn new(source: EntityId, kind: EdgeKind, target: EntityId) -> Self {
        Self {
            source,
            kind,
            target,
        }
    }

    /// Encodes the pinned 33-byte layout: source @ 0..16, kind u8 @ 16,
    /// target @ 17..33.
    #[must_use]
    pub fn encode(&self) -> [u8; EDGE_REF_LEN] {
        let mut out = [0_u8; EDGE_REF_LEN];
        out[..ENTITY_ID_LEN].copy_from_slice(self.source.as_bytes());
        out[ENTITY_ID_LEN] = self.kind as u8;
        out[ENTITY_ID_LEN + 1..].copy_from_slice(self.target.as_bytes());
        out
    }

    /// Decodes a 33-byte EdgeRef, rejecting wrong lengths, unregistered kind
    /// bytes, and reserved entity-id byte patterns with
    /// [`Error::InvalidProvenanceBody`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != EDGE_REF_LEN {
            return Err(Error::InvalidProvenanceBody("EdgeRef must be 33 bytes"));
        }
        let source = entity_id_from(&bytes[..ENTITY_ID_LEN], "EdgeRef source id")?;
        let kind = EdgeKind::try_from_u8(bytes[ENTITY_ID_LEN]).ok_or(
            Error::InvalidProvenanceBody("EdgeRef kind byte is not a registered EdgeKind"),
        )?;
        let target = entity_id_from(&bytes[ENTITY_ID_LEN + 1..], "EdgeRef target id")?;
        Ok(Self {
            source,
            kind,
            target,
        })
    }
}

impl From<EdgeRef> for ClaimSubject {
    fn from(value: EdgeRef) -> Self {
        Self::Edge {
            source: value.source,
            kind: value.kind,
            target: value.target,
        }
    }
}

fn entity_id_from(bytes: &[u8], context: &'static str) -> Result<EntityId> {
    let arr: [u8; ENTITY_ID_LEN] = bytes
        .try_into()
        .map_err(|_| Error::InvalidProvenanceBody(context))?;
    EntityId::from_bytes(arr).map_err(|_| Error::InvalidProvenanceBody(context))
}

/// Authoritative supersession status of an `edge.provenance` Claim
/// (contracts.ts `supersession_status`: proposed | confirmed | disputed |
/// retracted). Serialized as u8 in the MessagePack value record; mirrors
/// the edge's cached [`EdgeConfirmationStatus`] flag one-to-one.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SupersessionStatus {
    Proposed = 0,
    Confirmed = 1,
    Disputed = 2,
    Retracted = 3,
}

impl SupersessionStatus {
    /// Converts a raw byte into a status, rejecting values above 3.
    #[must_use]
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Proposed),
            1 => Some(Self::Confirmed),
            2 => Some(Self::Disputed),
            3 => Some(Self::Retracted),
            _ => None,
        }
    }
}
