//! Moved from `crates/oneiron/src/recovery/canonical/vocabulary.rs` (lib split R3: record types below the lib).
//! `oneiron` re-exports each item at its old path.

pub use crate::store::canonical_document::CanonicalDocumentFork;
pub use crate::store::canonical_document::CanonicalDocumentPin;
pub use crate::store::canonical_document::CanonicalDocumentPurge;
pub use crate::store::canonical_document::CanonicalDocumentReceipt;
pub use crate::store::canonical_document::CanonicalDocumentVersion;
pub use crate::store::canonical_document::CanonicalForkStatus;
pub use crate::store::canonical_document::CanonicalSettleVerb;
use serde::Deserialize;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntity {
    pub id: [u8; 16],
    /// The exact 25-byte envelope followed by the original binary body.
    pub blob: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTombstone {
    pub id: [u8; 16],
    pub deleted_at: u64,
    /// Pinned Oneiron tombstone binary, independent of CRDT operation encoding.
    pub value: Vec<u8>,
}

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
