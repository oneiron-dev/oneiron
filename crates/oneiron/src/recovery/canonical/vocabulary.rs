//! CRDT-independent canonical snapshot values and document history vocabulary.
//! The entry type is `CanonicalSnapshot`.
//! `super` owns scope-sensitive operations and forwards these definitions.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntity {
    pub id: [u8; 16],
    /// The exact 25-byte envelope followed by the original binary body.
    pub blob: Vec<u8>,
}

/// A source edge, never an edges_in row, vector or retrieval posting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalBaseEdge {
    pub source: [u8; 16],
    pub kind: u8,
    pub target: [u8; 16],
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTombstone {
    pub id: [u8; 16],
    pub deleted_at: u64,
    /// Pinned Oneiron tombstone binary, independent of CRDT operation encoding.
    pub value: Vec<u8>,
}

pub use crate::store::canonical_document::{
    CanonicalDocumentFork, CanonicalDocumentPin, CanonicalDocumentPurge, CanonicalDocumentReceipt,
    CanonicalDocumentVersion, CanonicalEntityDocument, CanonicalEntityDocumentHistory,
    CanonicalForkStatus, CanonicalSettleVerb,
};

/// World proof retained when a soft-deleted CLAIM has only its header left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalShellWorld {
    pub id: [u8; 16],
    pub world: [u8; 16],
}

/// One room turn row a base window carries (OF-522), under its map key,
/// kept as the window holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRoomTurn {
    pub key: String,
    pub row: Vec<u8>,
}

/// One room side row a base window carries (FIX 1794), under its map key,
/// kept as the window holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRoomFact {
    pub key: String,
    pub row: Vec<u8>,
}

/// One document quote pin a base window carries (FIX 853), under its map
/// key, kept as the window holds it. A pin on a document the snapshot
/// captures rides in that document's history instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalPinCarrier {
    pub key: String,
    pub row: Vec<u8>,
}

/// One owner-signed custody transition piece a base window carries
/// (OF-422): opaque signed and sealed bytes, kept as the window holds them,
/// with its place among its transition's pieces (Phase2 A).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCustodyTransition {
    pub id: [u8; 16],
    #[serde(default)]
    pub piece: u32,
    pub carrier: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalContainerManifest {
    pub container_id: String,
    pub container_kind: String,
    pub schema_version: u16,
    pub source_entity_id: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSchemaManifest {
    pub oneiron_schema_version: u16,
    /// Informational producer version. Rebuild does not import its binary format.
    pub loro_version: String,
    pub container_schema_version: u16,
    pub analyzer_manifest_blake3: [u8; 32],
}

/// Ordered source state. No op IDs, Loro exports, or Layer-2 indexes are
/// encoded, but for the version an entity document's origin names (FIX 3553).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalSnapshot {
    pub window: String,
    pub entity_blobs: Vec<CanonicalEntity>,
    pub retained_claim_worlds: Vec<CanonicalShellWorld>,
    pub base_edges: Vec<CanonicalBaseEdge>,
    pub tombstones: Vec<CanonicalTombstone>,
    pub doc_snapshots: Vec<CanonicalDocument>,
    pub entity_documents: Vec<CanonicalEntityDocument>,
    pub document_heads: Vec<CanonicalHead>,
    pub head_move_receipts: Vec<CanonicalHeadMove>,
    /// Durable workflows, with value-based merge bases instead of old frontiers.
    pub note_forks: Vec<crate::note::NoteFork>,
    pub note_proposals: Vec<crate::note::NoteReviewBundle>,
    pub container_manifests: Vec<CanonicalContainerManifest>,
    pub schema_manifest: CanonicalSchemaManifest,
    /// The window's TASKs one of whose authority facts the source refused,
    /// the fact's id having been deleted there first. The fact's body never
    /// reached the store, so this alone names the task, and its facts read
    /// as a refusal wherever the window is recovered. Absent when empty, so
    /// an artifact with none encodes as before.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub suppressed_tasks: Vec<[u8; 16]>,
    /// The base window's custody transitions (OF-422), by record id. Absent
    /// when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custody_transitions: Vec<CanonicalCustodyTransition>,
    /// The base window's room turn rows (OF-522), by map key. Absent when
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub room_turns: Vec<CanonicalRoomTurn>,
    /// The base window's room side rows (FIX 1794), by map key. Absent when
    /// empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub room_facts: Vec<CanonicalRoomFact>,
    /// The base window's document quote pins (FIX 853) on documents it does
    /// not capture, by map key. Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub document_pins: Vec<CanonicalPinCarrier>,
    /// The window's peer origins (FIX 4550), by row id, each naming its
    /// row's exact blob. Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peer_origins: Vec<CanonicalPeerOrigin>,
    /// The final rows' births (FIX 3069), by row id: the window's carrier,
    /// else the birth stamped here. Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub row_births: Vec<CanonicalRowBirth>,
    /// The window's withdrawal fences and session epoch floors (FIX 8820),
    /// by map key. Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withdrawn_cutoffs: Vec<CanonicalCutoff>,
    /// The window's by-reference ASSET body references (FIX 5489), by owner
    /// id, each binding the exact carrier `entity_blobs` holds for it.
    /// Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub asset_body_refs: Vec<CanonicalAssetBodyRef>,
    /// The final rows' source audience bindings and every revision of the
    /// policies they reach (Engine A), by map key. Absent when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub source_audiences: Vec<CanonicalSourceAudience>,
}
