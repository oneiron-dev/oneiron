//! CRDT-independent, byte-exact Layer-1 snapshot and fresh-window construction.

use std::collections::BTreeMap;

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::document::{self, CanonicalDocument, CanonicalHead, CanonicalHeadMove};
use super::validation;
use super::{decode_recovery_artifact, seal_recovery_artifact};
use crate::error::{ArtifactError, Error, Result};
use crate::ports::{
    DeletionMarker, EntityStoreRead, TombstoneStoreRead, WindowAddress, WindowDeletionRows,
};
use crate::{EntityId, Vault};

/// Canonical Layer-1 artifact discriminator (not a Loro snapshot).
pub const CANONICAL_SNAPSHOT_ARTIFACT_TYPE: u16 = 1;
/// Maximum decoded artifact size. Recovery is off the hot path but remains bounded.
pub const CANONICAL_SNAPSHOT_MAX_BYTES: usize = 64 * 1024 * 1024;

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
impl CanonicalBaseEdge {
    pub(super) fn key(&self) -> Result<String> {
        Ok(format!(
            "{}:{:02}:{}",
            id(self.source)?.to_hex(),
            self.kind,
            id(self.target)?.to_hex()
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalTombstone {
    pub id: [u8; 16],
    pub deleted_at: u64,
    /// Pinned Oneiron tombstone binary, independent of CRDT operation encoding.
    pub value: Vec<u8>,
}

/// Current generic EntityDoc value, independent of the document's Loro op log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntityDocument {
    pub entity_id: [u8; 16],
    pub document_id: [u8; 16],
    /// None is a UTF-8 body; Some is the document's MessagePack body field.
    pub field: Option<String>,
    pub text: String,
    /// Editable fields, each encoded as one MessagePack value.
    pub metadata: BTreeMap<String, Vec<u8>>,
    /// Native record fields projected by the immutable adapter at birth.
    pub record_fields: Vec<String>,
    pub birth_actor: [u8; 16],
    pub birth_at: u64,
    /// The document's causal state, by value. Absent for a document with no
    /// fork, pin, receipt or purge: that one is its current value alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<CanonicalEntityDocumentHistory>,
}

impl CanonicalEntityDocument {
    /// The bytes this row holds: its ids, text and causal history.
    pub(super) fn held(&self) -> usize {
        self.entity_id.len()
            + self.document_id.len()
            + self.field.as_ref().map_or(0, String::len)
            + self.text.len()
            + metadata_size(&self.metadata)
            + self.record_fields.iter().map(String::len).sum::<usize>()
            + self.history.as_ref().map_or(0, |history| {
                let versions = history.versions.iter().map(|version| {
                    16 + 4 * version.parents.len()
                        + version.middle.len()
                        + metadata_size(&version.metadata)
                });
                let pins = history.pins.iter().map(|pin| 96 + pin.quote.len());
                let forks = history.forks.iter().map(|fork| {
                    96 + fork.output.as_ref().map_or(0, String::len)
                        + fork.output_metadata.as_ref().map_or(0, metadata_size)
                });
                versions.sum::<usize>()
                    + pins.sum::<usize>()
                    + forks.sum::<usize>()
                    + 96 * (history.receipts.len() + history.purges.len())
            })
    }
}

fn metadata_size(fields: &BTreeMap<String, Vec<u8>>) -> usize {
    fields
        .iter()
        .map(|(field, value)| field.len() + value.len())
        .sum()
}

/// The causal state of a generic EntityDoc, CRDT-independent: the retained
/// versions its citations, receipts, forks and purges name, never Loro
/// frontiers, cursors or exports. A restore replays the versions into fresh
/// history and binds every row to its replayed version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEntityDocumentHistory {
    /// Retained versions in canonical causal order. Every version precedes
    /// the last, which is the live head.
    pub versions: Vec<CanonicalDocumentVersion>,
    /// An owner purge dropped the history before version 0: none is carried,
    /// and the restored document refuses every older version.
    pub shallow: bool,
    pub pins: Vec<CanonicalDocumentPin>,
    pub receipts: Vec<CanonicalDocumentReceipt>,
    pub forks: Vec<CanonicalDocumentFork>,
    pub purges: Vec<CanonicalDocumentPurge>,
}

/// One retained version: the earlier versions it directly follows, and its
/// text as one splice of its first parent's text (of the empty text for a
/// version with no parent).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentVersion {
    pub parents: Vec<u32>,
    /// Characters kept from the start of the first parent's text.
    pub prefix: u32,
    /// Characters kept from its end.
    pub suffix: u32,
    pub middle: String,
    pub metadata: BTreeMap<String, Vec<u8>>,
}

/// An immutable citation pin: the quoted span of one version, in characters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentPin {
    pub citation: [u8; 16],
    pub document: [u8; 16],
    pub actor: [u8; 16],
    pub version: u32,
    pub start: u32,
    pub end: u32,
    pub quote: String,
    pub hash: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalSettleVerb {
    Merge,
    Switch,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CanonicalForkStatus {
    Pending,
    Merged,
    Switched,
    Rejected,
}

/// A settlement or direct-update receipt between two versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentReceipt {
    pub receipt: [u8; 16],
    pub proposal: [u8; 16],
    pub fork: [u8; 16],
    pub actor: [u8; 16],
    pub verb: CanonicalSettleVerb,
    pub at: u64,
    pub before: u32,
    pub after: u32,
}

/// A fork and its place in its proposal bundle, which the snapshot carries
/// whole or refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentFork {
    pub fork: [u8; 16],
    pub proposal: [u8; 16],
    pub parent_document: [u8; 16],
    pub actor: [u8; 16],
    pub opened_at: u64,
    pub rewrite: bool,
    pub status: CanonicalForkStatus,
    /// None only for a settled fork whose base a purge dropped.
    pub base: Option<u32>,
    /// The retained output text of a pending fork.
    pub output: Option<String>,
    pub output_metadata: Option<BTreeMap<String, Vec<u8>>>,
    pub proposal_index: u16,
    pub proposal_len: u16,
    pub proposal_settled: bool,
}

/// Durable proof of one owner purge, bound to the versions it named.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocumentPurge {
    pub receipt: [u8; 16],
    pub document: [u8; 16],
    pub actor: [u8; 16],
    pub requested: u32,
    pub applied: u32,
    pub at: u64,
    pub live_text_hash: [u8; 32],
}

impl CanonicalEntityDocumentHistory {
    /// Every version's full text, rebuilt from its splice, in version order.
    pub fn texts(&self) -> Result<Vec<String>> {
        let mut texts: Vec<String> = Vec::with_capacity(self.versions.len());
        for (index, version) in self.versions.iter().enumerate() {
            let base: Vec<char> = match version.parents.first() {
                None => Vec::new(),
                Some(&parent) => {
                    let parent = parent as usize;
                    if parent >= index {
                        return Err(invalid("entity document version parent"));
                    }
                    texts[parent].chars().collect()
                }
            };
            let prefix = version.prefix as usize;
            let suffix = version.suffix as usize;
            if prefix
                .checked_add(suffix)
                .is_none_or(|kept| kept > base.len())
            {
                return Err(invalid("entity document version splice"));
            }
            let mut text: String = base[..prefix].iter().collect();
            text.push_str(&version.middle);
            text.extend(&base[base.len() - suffix..]);
            texts.push(text);
        }
        Ok(texts)
    }

    /// The splice that turns `parent` into `text`: the longest common prefix,
    /// then the longest common suffix of what remains.
    pub fn splice(parent: &str, text: &str) -> Result<CanonicalDocumentVersion> {
        let old: Vec<char> = parent.chars().collect();
        let new: Vec<char> = text.chars().collect();
        let prefix = old.iter().zip(&new).take_while(|(a, b)| a == b).count();
        let suffix = old[prefix..]
            .iter()
            .rev()
            .zip(new[prefix..].iter().rev())
            .take_while(|(a, b)| a == b)
            .count();
        Ok(CanonicalDocumentVersion {
            parents: Vec::new(),
            prefix: u32::try_from(prefix).map_err(|_| invalid("entity document version size"))?,
            suffix: u32::try_from(suffix).map_err(|_| invalid("entity document version size"))?,
            middle: new[prefix..new.len() - suffix].iter().collect(),
            metadata: BTreeMap::new(),
        })
    }
}

/// World proof retained when a soft-deleted CLAIM has only its header left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalShellWorld {
    pub id: [u8; 16],
    pub world: [u8; 16],
}

/// One room turn row a base window carries (OF-522), kept as the window holds
/// it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalRoomTurn {
    pub id: [u8; 16],
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

/// One owner-signed custody transition a base window carries (OF-422): opaque
/// signed and sealed bytes, kept as the window holds them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalCustodyTransition {
    pub id: [u8; 16],
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

/// Ordered source state. No op IDs, Loro exports, or Layer-2 indexes are encoded.
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
    /// The base window's room turn rows (OF-522), by turn id. Absent when
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
}

impl CanonicalSnapshot {
    /// Validate every section and reference before any reconstruction or storage write.
    pub fn validate(&self) -> Result<()> {
        validation::validate(self)
    }

    /// Deterministic MessagePack, protected by the blake3 artifact envelope.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.encode_within(CANONICAL_SNAPSHOT_MAX_BYTES)
    }

    /// [`Self::encode`], refused with [`ArtifactError::OverlayLimit`] once the
    /// artifact would pass `limit` bytes. The payload is written straight
    /// into the artifact's one buffer, which stops growing at the limit, so
    /// an artifact too large is never held whole before it is refused.
    pub(crate) fn encode_within(&self, limit: usize) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = BoundedWriter {
            bytes: Vec::new(),
            budget: ByteBudget::new(limit.min(CANONICAL_SNAPSHOT_MAX_BYTES)),
            refused: None,
        };
        // Room for the envelope header, sealed once the payload is written.
        std::io::Write::write_all(&mut out, &[0; super::HEADER_LEN]).map_err(|_| out.refusal())?;
        rmp_serde::encode::write_named(&mut out, self).map_err(|_| out.refusal())?;
        seal_recovery_artifact(CANONICAL_SNAPSHOT_ARTIFACT_TYPE, &mut out.bytes);
        Ok(out.bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        check_size(bytes.len())?;
        let artifact = decode_recovery_artifact(bytes, CANONICAL_SNAPSHOT_ARTIFACT_TYPE)?;
        let value: Self =
            rmp_serde::from_slice(artifact.payload()).map_err(|_| invalid("canonical payload"))?;
        value.validate()?;
        if pack(&value)? != artifact.payload() {
            return Err(invalid("noncanonical payload or trailing bytes"));
        }
        Ok(value)
    }

    pub fn blake3(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&self.encode()?).as_bytes())
    }

    pub(super) fn refresh_containers(&mut self) {
        self.container_manifests = self.expected_containers();
    }
    pub(super) fn expected_containers(&self) -> Vec<CanonicalContainerManifest> {
        let mut rows = Vec::new();
        for name in [
            "entities",
            "edges",
            "tombstones",
            "retained_claim_worlds",
            "documents",
            "entity_documents",
            "document_heads",
            "head_move_receipts",
            "note_forks",
            "note_proposals",
            "custody",
            "room_turns",
            "room_facts",
            "document_pins",
        ] {
            rows.push(CanonicalContainerManifest {
                container_id: name.to_owned(),
                container_kind: "map".to_owned(),
                schema_version: 1,
                source_entity_id: None,
            });
        }
        for doc in &self.entity_documents {
            for (name, kind) in [("body", "text"), ("meta", "map")] {
                rows.push(CanonicalContainerManifest {
                    container_id: format!(
                        "entity_doc/{}/{name}",
                        crate::entity_id::bytes_to_hex_lower(&doc.entity_id)
                    ),
                    container_kind: kind.to_owned(),
                    schema_version: 1,
                    source_entity_id: Some(doc.entity_id),
                });
            }
        }
        for doc in &self.doc_snapshots {
            for (name, kind) in [("body", "text"), ("note", "map"), ("authorship", "map")] {
                rows.push(CanonicalContainerManifest {
                    container_id: format!("{}/{name}", doc.key()),
                    container_kind: kind.to_owned(),
                    schema_version: 1,
                    source_entity_id: Some(doc.entity_id),
                });
            }
        }
        rows.sort_by(|a, b| a.container_id.cmp(&b.container_id));
        rows
    }
}

/// Marks first, as every local removal does, the task of an authority fact
/// this vault never admitted that a deleted id's carrier holds: the capture
/// below leaves that carrier out of the artifact or keeps only its shell, and
/// the mark is what then carries the refusal in `suppressed_tasks`. An id is
/// deleted here when the window or a pending marker holds its tombstone, or a
/// global hard marker names it, as the capture reads them. A build without
/// sync captures too, so it marks through the same writer.
fn mark_deleted_carriers_first(
    vault: &Vault,
    window: &str,
    snapshot: &CanonicalSnapshot,
) -> Result<()> {
    let mut deleted: std::collections::BTreeSet<_> =
        snapshot.tombstones.iter().map(|row| row.id).collect();
    {
        let txn = vault.store.env.read_txn()?;
        for row in vault
            .store
            .port_pending_tombstones_in_window(&txn, WindowAddress::new(window))?
        {
            deleted.insert(*row?.id.as_bytes());
        }
        for row in &snapshot.entity_blobs {
            if vault
                .store
                .port_deletion_marked(&txn, DeletionMarker::HardDelete, &id(row.id)?)?
            {
                deleted.insert(row.id);
            }
        }
    }
    let carriers = snapshot
        .entity_blobs
        .iter()
        .filter(|row| {
            deleted.contains(&row.id)
                && crate::batch::EntityMetadataHeader::parse(&row.blob)
                    .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_TASK)
        })
        .map(|row| Ok((id(row.id)?, row.blob.clone())))
        .collect::<Result<Vec<_>>>()?;
    #[cfg(feature = "sync")]
    crate::sync::window::mark_removed_carriers_first(
        vault,
        crate::sync::window::CarrierRemoval::CanonicalCapture,
        &carriers,
    )?;
    #[cfg(not(feature = "sync"))]
    crate::task_authority::mark_removed_carriers(vault, &carriers)?;
    Ok(())
}

/// Captures a quiescent window plus every NOTE document and head receipt in its scope.
/// The caller must stop window writers while taking this off-hot-path snapshot.
pub fn capture_canonical_window(
    vault: &Vault,
    window: &str,
    doc: &LoroDoc,
) -> Result<CanonicalSnapshot> {
    capture_canonical_window_within(vault, window, doc, usize::MAX)
}

/// [`capture_canonical_window`] holding at most `limit` bytes of copies: the
/// window's rows and their keys, documents, receipts and NOTE workflows. A
/// copy that would pass `limit` is refused with
/// [`ArtifactError::OverlayLimit`] before it is made, so the copies of a
/// window far over the limit cost the limit, not the window. One document
/// is read whole before it is counted, as opening it reads it.
pub(crate) fn capture_canonical_window_within(
    vault: &Vault,
    window: &str,
    doc: &LoroDoc,
    limit: usize,
) -> Result<CanonicalSnapshot> {
    let budget = &mut ByteBudget::new(limit);
    // The shallow value names the roots without copying what they hold.
    let LoroValue::Map(containers) = doc.get_value() else {
        return Err(invalid("window root"));
    };
    if containers.keys().any(|name| {
        ![
            "entities",
            "edges",
            "tombstones",
            "retained_claim_worlds",
            "documents",
            "entity_documents",
            "document_heads",
            "head_move_receipts",
            "note_forks",
            "note_proposals",
            "row_births",
            "custody",
            "room_turns",
            "room_facts",
            "document_pins",
            "withdrawn_cutoffs",
        ]
        .contains(&name.as_str())
    }) {
        return Err(invalid("unknown Layer-1 window container"));
    }
    let mut snapshot = CanonicalSnapshot {
        window: window.to_owned(),
        entity_blobs: Vec::new(),
        retained_claim_worlds: Vec::new(),
        base_edges: Vec::new(),
        tombstones: Vec::new(),
        doc_snapshots: Vec::new(),
        entity_documents: Vec::new(),
        document_heads: Vec::new(),
        head_move_receipts: Vec::new(),
        note_forks: Vec::new(),
        note_proposals: Vec::new(),
        container_manifests: Vec::new(),
        schema_manifest: CanonicalSchemaManifest {
            oneiron_schema_version: crate::store::STORAGE_ABI_VERSION,
            loro_version: "1.13.9".to_owned(),
            container_schema_version: 1,
            analyzer_manifest_blake3: *blake3::hash(
                vault
                    .analyzer
                    .manifest()
                    .canonical_json()
                    .map_err(|_| invalid("analyzer manifest"))?
                    .as_bytes(),
            )
            .as_bytes(),
        },
        suppressed_tasks: Vec::new(),
        custody_transitions: Vec::new(),
        room_turns: Vec::new(),
        room_facts: Vec::new(),
        document_pins: Vec::new(),
    };
    for (key, blob) in binary_rows_within(doc, "entities", budget)? {
        snapshot.entity_blobs.push(CanonicalEntity {
            id: parse_id(&key)?,
            blob,
        });
    }
    for (key, value) in binary_rows_within(doc, "edges", budget)? {
        let parts: Vec<_> = key.split(':').collect();
        if parts.len() != 3 {
            return Err(invalid("edge key"));
        }
        let edge = CanonicalBaseEdge {
            source: parse_id(parts[0])?,
            kind: parts[1].parse().map_err(|_| invalid("edge kind"))?,
            target: parse_id(parts[2])?,
            value,
        };
        if edge.key()? != key {
            return Err(invalid("noncanonical edge key"));
        }
        snapshot.base_edges.push(edge);
    }
    for (key, row) in binary_rows_within(doc, "room_turns", budget)? {
        snapshot.room_turns.push(CanonicalRoomTurn {
            id: parse_id(&key)?,
            row,
        });
    }
    for (key, row) in binary_rows_within(doc, "room_facts", budget)? {
        snapshot.room_facts.push(CanonicalRoomFact { key, row });
    }
    for (key, carrier) in binary_rows_within(doc, "custody", budget)? {
        snapshot
            .custody_transitions
            .push(CanonicalCustodyTransition {
                id: parse_id(&key)?,
                carrier,
            });
    }
    for (key, value) in binary_rows_within(doc, "tombstones", budget)? {
        snapshot.tombstones.push(CanonicalTombstone {
            id: parse_id(&key)?,
            deleted_at: crate::deletion::decode_tombstone_value(&value).deleted_at,
            value,
        });
    }
    mark_deleted_carriers_first(vault, window, &snapshot)?;
    let txn = vault.store.env.read_txn()?;
    // Pending delete intent is Layer 1 even when a crash preceded CRDT publication.
    for row in vault
        .store
        .port_pending_tombstones_in_window(&txn, WindowAddress::new(window))?
    {
        let row = row?;
        let entity = *row.id.as_bytes();
        let value = row.raw;
        if let Some(previous) = snapshot.tombstones.iter_mut().find(|row| row.id == entity) {
            if crate::deletion::decode_tombstone_value(&previous.value).is_hard()
                && !crate::deletion::decode_tombstone_value(&value).is_hard()
            {
                continue;
            }
            previous.deleted_at = crate::deletion::decode_tombstone_value(&value).deleted_at;
            previous.value = value;
        } else {
            budget.take(entity.len() + value.len())?;
            snapshot.tombstones.push(CanonicalTombstone {
                id: entity,
                deleted_at: crate::deletion::decode_tombstone_value(&value).deleted_at,
                value,
            });
        }
    }
    // A global hard marker outranks stale window content and soft tombstones,
    // including ids whose body is no longer present in the window map.
    let candidates: std::collections::BTreeSet<_> = snapshot
        .entity_blobs
        .iter()
        .map(|row| row.id)
        .chain(snapshot.tombstones.iter().map(|row| row.id))
        .collect();
    for entity in candidates {
        if let Some(value) =
            vault
                .store
                .port_deletion_marker(&txn, DeletionMarker::HardDelete, &id(entity)?)?
        {
            if !crate::deletion::decode_tombstone_value(&value).is_hard() {
                return Err(invalid("invalid hard delete marker"));
            }
            snapshot.tombstones.retain(|row| row.id != entity);
            snapshot.tombstones.push(CanonicalTombstone {
                id: entity,
                deleted_at: crate::deletion::decode_tombstone_value(&value).deleted_at,
                value,
            });
        }
    }
    // A row this vault fenced as deleted, whose tombstone the window no longer
    // holds, was a delete a peer withdrew. A soft tombstone cannot be rebuilt
    // faithfully, and exporting the row would make it live wherever the
    // artifact lands, so the snapshot is refused. The stored row decides, as
    // on every read: a delete-protected record stays live under a fence a
    // peer's tombstone planted before it arrived.
    for row in &snapshot.entity_blobs {
        if snapshot
            .tombstones
            .iter()
            .any(|tombstone| tombstone.id == row.id)
        {
            continue;
        }
        let entity = id(row.id)?;
        // Borrowed: only the stored row's header decides, so the body of a
        // projection under repair is never copied to answer it.
        let marked = match vault.store.port_entity_with_raw(&txn, &entity, |stored| {
            crate::deletion::row_deletion_marked(&vault.store, &txn, &entity, Some(stored))
        })? {
            Some(marked) => marked,
            None => crate::deletion::row_deletion_marked(&vault.store, &txn, &entity, None)?,
        };
        if marked {
            return Err(invalid("deleted row without its tombstone"));
        }
    }
    // Audit identity is the validated LOCAL receipt index, not the peer's
    // entity header or tombstone inventory. A rejected type-change (e.g. an
    // ASSET at this ID) must not become a canonical replacement, and removal
    // of the CRDT map key must not hide a committed event from a fresh vault.
    let mut protected_receipts = std::collections::BTreeSet::new();
    let mut restored_receipts = Vec::new();
    let receipts =
        crate::receipt::canonical_records_in_window(&vault.store, &txn, window, |raw| {
            budget.take(16 + raw.len())
        })?;
    for (receipt_id, local_blob) in receipts {
        let bytes = *receipt_id.as_bytes();
        if let Some(candidate) = snapshot.entity_blobs.iter().find(|row| row.id == bytes) {
            if candidate.blob != local_blob {
                return Err(Error::CorruptedIndex(
                    "canonical receipt record carrier diverged",
                ));
            }
        } else {
            restored_receipts.push(CanonicalEntity {
                id: bytes,
                blob: local_blob,
            });
        }
        protected_receipts.insert(bytes);
    }
    // A receipt-shaped CRDT row that never passed local audit admission is
    // not a source of deletion immunity or an exportable receipt. Refuse the
    // snapshot rather than shipping an artifact whose rebuild will discard it.
    for row in &snapshot.entity_blobs {
        if crate::batch::EntityMetadataHeader::parse(&row.blob)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_RECEIPT_RECORD)
            && !protected_receipts.contains(&row.id)
        {
            return Err(Error::CorruptedIndex(
                "canonical receipt record not materialized",
            ));
        }
    }
    snapshot.entity_blobs.extend(restored_receipts);
    snapshot
        .tombstones
        .retain(|row| !protected_receipts.contains(&row.id));

    // Hard deletion removes the payload and graph. Soft deletion retains only
    // the exact header and surviving Layer-1 edges, never an old body. The live
    // map may have removed that header already, so recover it from the store.
    let hard: std::collections::BTreeSet<_> = snapshot
        .tombstones
        .iter()
        .filter(|row| crate::deletion::decode_tombstone_value(&row.value).is_hard())
        .map(|row| row.id)
        .collect();
    snapshot.entity_blobs.retain(|row| !hard.contains(&row.id));
    snapshot
        .base_edges
        .retain(|row| !hard.contains(&row.source) && !hard.contains(&row.target));
    for tombstone in &snapshot.tombstones {
        if hard.contains(&tombstone.id) {
            continue;
        }
        let id = EntityId::from_bytes(tombstone.id)?;
        let shell = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, &txn, &id)?
            .ok_or(invalid("missing retained shell"))?;
        if shell.len() != crate::batch::ENTITY_METADATA_HEADER_LEN {
            return Err(invalid("soft delete not materialized"));
        }
        snapshot.entity_blobs.retain(|row| row.id != tombstone.id);
        snapshot.entity_blobs.push(CanonicalEntity {
            id: tombstone.id,
            blob: shell.to_vec(),
        });
    }
    // Only outgoing BaseEdge rows are source records. Never promote edges_in
    // (a Layer-2 reverse index) to canonical truth when recovering a shell.
    let soft: std::collections::BTreeSet<_> = snapshot
        .tombstones
        .iter()
        .filter(|row| !hard.contains(&row.id))
        .map(|row| row.id)
        .collect();
    if !soft.is_empty() {
        snapshot
            .base_edges
            .retain(|row| !soft.contains(&row.source) && !soft.contains(&row.target));
        for row in crate::ports::EdgeStoreInventory::port_edge_rows_raw(&vault.store, &txn)? {
            let (key, value) = row?;
            if key.len() != 33 {
                return Err(invalid("retained edge key"));
            }
            let source: [u8; 16] = key[..16]
                .try_into()
                .map_err(|_| invalid("retained edge source"))?;
            let target: [u8; 16] = key[17..]
                .try_into()
                .map_err(|_| invalid("retained edge target"))?;
            if (soft.contains(&source) || soft.contains(&target))
                && !hard.contains(&source)
                && !hard.contains(&target)
            {
                budget.take(key.len() + value.len())?;
                snapshot.base_edges.push(CanonicalBaseEdge {
                    source,
                    kind: key[16],
                    target,
                    value: value.to_vec(),
                });
            }
        }
    }
    document::capture(vault, &txn, &mut snapshot, budget)?;
    #[cfg(feature = "sync")]
    for entity in &snapshot.entity_blobs {
        if crate::batch::EntityMetadataHeader::parse(&entity.blob)
            .is_some_and(|h| h.entity_type != crate::registry::ENTITY_TYPE_NOTE)
            && let Some(row) = crate::entity_doc::capture_canonical(vault, &txn, entity.id)?
        {
            budget.take(row.held())?;
            snapshot.entity_documents.push(row);
        }
    }
    snapshot.entity_documents.sort_by_key(|row| row.entity_id);
    // FIX 853: the pins the window carries on documents not captured above.
    #[cfg(feature = "sync")]
    {
        let documents = snapshot
            .entity_documents
            .iter()
            .map(|row| id(row.entity_id))
            .collect::<Result<std::collections::BTreeSet<_>>>()?;
        let rows = binary_rows_within(doc, "document_pins", budget)?;
        for (key, row) in
            crate::sync::document_pins::canonical_pin_rows(vault, &txn, rows, &documents)?
        {
            snapshot
                .document_pins
                .push(CanonicalPinCarrier { key, row });
        }
    }
    snapshot.entity_blobs.sort_by_key(|row| row.id);
    // Only a TASK row carries a refusal: a forged fact may name any id as its
    // task, and the artifact's validation refuses a mark on anything else.
    for entity in &snapshot.entity_blobs {
        if crate::batch::EntityMetadataHeader::parse(&entity.blob)
            .is_some_and(|header| header.entity_type == crate::registry::ENTITY_TYPE_TASK)
            && crate::task_authority::fact_suppressed_in(&vault.store, &txn, &id(entity.id)?)?
        {
            snapshot.suppressed_tasks.push(entity.id);
        }
    }
    let carried: std::collections::BTreeMap<_, _> =
        binary_rows_within(doc, "retained_claim_worlds", budget)?
            .into_iter()
            .collect();
    if let Some((_, hex)) = window.split_once('@') {
        let world = EntityId::from_hex(hex).map_err(|_| invalid("window world"))?;
        for entity in &snapshot.entity_blobs {
            let header = crate::batch::EntityMetadataHeader::parse(&entity.blob)
                .ok_or(invalid("entity metadata"))?;
            if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
                || entity.blob.len() != crate::batch::ENTITY_METADATA_HEADER_LEN
            {
                continue;
            }
            if vault
                .store
                .port_deletion_marker(&txn, DeletionMarker::WindowAddress, &id(entity.id)?)?
                .as_deref()
                != Some(window.as_bytes())
                && carried.get(&id(entity.id)?.to_hex()).map(Vec::as_slice)
                    != Some(world.as_bytes().as_slice())
            {
                return Err(invalid("soft claim world address"));
            }
            snapshot.retained_claim_worlds.push(CanonicalShellWorld {
                id: entity.id,
                world: *world.as_bytes(),
            });
        }
    }
    if carried.keys().any(|id| {
        !snapshot.retained_claim_worlds.iter().any(|row| {
            EntityId::from_bytes(row.id)
                .ok()
                .is_some_and(|entity| entity.to_hex() == *id)
        })
    }) {
        return Err(invalid("orphan retained world witness"));
    }
    snapshot
        .base_edges
        .sort_by_key(|row| (row.source, row.kind, row.target));
    snapshot.tombstones.sort_by_key(|row| row.id);
    snapshot.refresh_containers();
    snapshot.validate()?;
    for edge in &snapshot.base_edges {
        if edge.kind == crate::EdgeKind::AddressedTo as u8
            && super::trusted_soft_addressing_edge(
                &snapshot,
                &id(edge.source)?,
                &id(edge.target)?,
                &edge.value,
            )?
            && crate::batch::stored_entity_type(&vault.store, &txn, &id(edge.target)?)?
                != Some(crate::registry::ENTITY_TYPE_PERSON)
        {
            return Err(invalid(
                "retained addressing recipient missing or not a PERSON",
            ));
        }
    }
    Ok(snapshot)
}

/// Reconstructs Layer 1 from values, not by importing an old CRDT snapshot.
/// Available without `sync`; the sync materialization door consumes this same doc.
pub fn rebuild_vault_window_from_canonical(snapshot: &CanonicalSnapshot) -> Result<LoroDoc> {
    snapshot.validate()?;
    let doc = LoroDoc::new();
    for entity in &snapshot.entity_blobs {
        insert(&doc, "entities", &id(entity.id)?.to_hex(), &entity.blob)?;
    }
    for shell in &snapshot.retained_claim_worlds {
        insert(
            &doc,
            "retained_claim_worlds",
            &id(shell.id)?.to_hex(),
            &shell.world,
        )?;
    }
    for edge in &snapshot.base_edges {
        insert(&doc, "edges", &edge.key()?, &edge.value)?;
    }
    for row in &snapshot.custody_transitions {
        insert(&doc, "custody", &id(row.id)?.to_hex(), &row.carrier)?;
    }
    for row in &snapshot.room_turns {
        insert(&doc, "room_turns", &id(row.id)?.to_hex(), &row.row)?;
    }
    for row in &snapshot.room_facts {
        insert(&doc, "room_facts", &row.key, &row.row)?;
    }
    for row in &snapshot.document_pins {
        insert(&doc, "document_pins", &row.key, &row.row)?;
    }
    for tombstone in &snapshot.tombstones {
        insert(
            &doc,
            "tombstones",
            &id(tombstone.id)?.to_hex(),
            &tombstone.value,
        )?;
    }
    // An explicit document carrier scopes replacement even for an inline NOTE
    // with no document rows. Ordinary sync windows have no such carrier.
    doc.get_map("documents");
    // Documents are canonical records inside the window; each is reconstructed
    // into its own fresh LoroDoc by the ordinary forward document pass.
    for document in &snapshot.doc_snapshots {
        insert(&doc, "documents", &document.key(), &pack(document)?)?;
    }
    for row in &snapshot.entity_documents {
        insert(
            &doc,
            "entity_documents",
            &id(row.entity_id)?.to_hex(),
            &pack(row)?,
        )?;
    }
    for head in &snapshot.document_heads {
        insert(
            &doc,
            "document_heads",
            &id(head.entity_id)?.to_hex(),
            &pack(head)?,
        )?;
    }
    for receipt in &snapshot.head_move_receipts {
        insert(
            &doc,
            "head_move_receipts",
            &id(receipt.id)?.to_hex(),
            &pack(receipt)?,
        )?;
    }
    for fork in &snapshot.note_forks {
        insert(&doc, "note_forks", &fork.fork.to_hex(), &pack(fork)?)?;
    }
    for bundle in &snapshot.note_proposals {
        insert(&doc, "note_proposals", &bundle.id.to_hex(), &pack(bundle)?)?;
    }
    doc.commit();
    Ok(doc)
}

#[cfg(feature = "sync")]
pub(super) fn binary_rows(doc: &LoroDoc, name: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    binary_rows_within(doc, name, &mut ByteBudget::new(usize::MAX))
}

/// The shortest key a Layer-1 window map holds: one hex entity id.
const ROW_KEY_BYTES: usize = 32;

/// The binary rows of the window map `name`, copying no row past `budget`.
fn binary_rows_within(
    doc: &LoroDoc,
    name: &str,
    budget: &mut ByteBudget,
) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut rows = BTreeMap::new();
    let LoroValue::Map(containers) = doc.get_value() else {
        return Err(invalid("window root"));
    };
    // Looking up a root by name creates it in Loro, even without an op. Readers
    // must inspect the existing root IDs so validation cannot change the document.
    let map = match containers.get(name) {
        None => return Ok(rows),
        Some(LoroValue::Container(id)) => doc
            .try_get_map(id)
            .ok_or(invalid("nonmap Layer-1 carrier"))?,
        Some(_) => return Err(invalid("nonmap Layer-1 carrier")),
    };
    // The map walk lists every key before its first row, so the keys are
    // admitted first, each at the shortest key a Layer-1 map holds.
    budget.take(map.len().saturating_mul(ROW_KEY_BYTES))?;
    let mut failed = false;
    let mut refused = None;
    map.for_each(|key, value| match value {
        _ if refused.is_some() => {}
        ValueOrContainer::Value(LoroValue::Binary(value)) => {
            match budget.take(key.len().saturating_sub(ROW_KEY_BYTES) + value.len()) {
                Ok(()) => {
                    rows.insert(key.to_owned(), value.to_vec());
                }
                Err(error) => refused = Some(error),
            }
        }
        _ => failed = true,
    });
    if failed {
        return Err(invalid("nonbinary Layer-1 carrier"));
    }
    match refused {
        Some(error) => Err(error),
        None => Ok(rows),
    }
}
pub(super) fn insert(doc: &LoroDoc, map: &str, key: &str, bytes: &[u8]) -> Result<()> {
    doc.get_map(map)
        .insert(key, bytes)
        .map_err(|_| invalid("rebuild map"))
}
pub(super) fn id(bytes: [u8; 16]) -> Result<EntityId> {
    EntityId::from_bytes(bytes)
}
pub(super) fn parse_id(value: &str) -> Result<[u8; 16]> {
    let parsed = EntityId::from_hex(value)?;
    if parsed.to_hex() != value {
        return Err(invalid("noncanonical entity id"));
    }
    Ok(*parsed.as_bytes())
}
pub(super) fn pack<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    rmp_serde::to_vec_named(value).map_err(|_| invalid("canonical encoding"))
}
pub(super) fn invalid(reason: &'static str) -> Error {
    ArtifactError::InvalidRecoveryArtifact(reason).into()
}

/// The bytes one capture or encoding has copied, refused with
/// [`ArtifactError::OverlayLimit`] before a copy would pass `limit`.
#[derive(Debug)]
pub(super) struct ByteBudget {
    held: usize,
    limit: usize,
}

impl ByteBudget {
    pub(super) const fn new(limit: usize) -> Self {
        Self { held: 0, limit }
    }

    /// Admits `bytes` more, before they are copied.
    pub(super) fn take(&mut self, bytes: usize) -> Result<()> {
        let held = self.held.saturating_add(bytes);
        if held > self.limit {
            return Err(ArtifactError::OverlayLimit {
                required: held,
                limit: self.limit,
            }
            .into());
        }
        self.held = held;
        #[cfg(test)]
        held_bytes::note(held);
        Ok(())
    }
}

/// The artifact's one buffer: a write past its budget is refused, and the
/// buffer never reserves past the budget either.
struct BoundedWriter {
    bytes: Vec<u8>,
    budget: ByteBudget,
    refused: Option<Error>,
}

impl BoundedWriter {
    /// Why a write failed: the budget it would pass, else the encoder.
    fn refusal(&mut self) -> Error {
        self.refused
            .take()
            .unwrap_or_else(|| invalid("canonical encoding"))
    }
}

impl std::io::Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Err(error) = self.budget.take(buf.len()) {
            self.refused = Some(error);
            return Err(std::io::ErrorKind::OutOfMemory.into());
        }
        let need = self.bytes.len() + buf.len();
        if need > self.bytes.capacity() {
            let grown = need
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.budget.limit);
            self.bytes.reserve_exact(grown - self.bytes.len());
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn check_size(size: usize) -> Result<()> {
    if size > CANONICAL_SNAPSHOT_MAX_BYTES {
        return Err(ArtifactError::OverlayLimit {
            required: size,
            limit: CANONICAL_SNAPSHOT_MAX_BYTES,
        }
        .into());
    }
    Ok(())
}

/// Test hook: the most bytes any one capture or encoding held.
#[cfg(test)]
pub(super) mod held_bytes {
    use std::cell::Cell;

    thread_local!(static PEAK: Cell<usize> = const { Cell::new(0) });

    pub(super) fn note(held: usize) {
        PEAK.with(|peak| peak.set(peak.get().max(held)));
    }

    /// The peak since the last call; the next count starts from zero.
    #[cfg(feature = "sync")]
    pub(in crate::recovery) fn take_peak() -> usize {
        PEAK.with(|peak| peak.replace(0))
    }
}
