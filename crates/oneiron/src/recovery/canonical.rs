//! CRDT-independent, byte-exact Layer-1 snapshot and fresh-window construction.

use std::collections::BTreeMap;

use loro::{LoroDoc, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};

use super::document::{self, CanonicalDocument, CanonicalHead, CanonicalHeadMove};
use super::validation;
use super::{decode_recovery_artifact, encode_recovery_artifact};
use crate::error::{ArtifactError, Error, Result};
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
    pub base_edges: Vec<CanonicalBaseEdge>,
    pub tombstones: Vec<CanonicalTombstone>,
    pub doc_snapshots: Vec<CanonicalDocument>,
    pub document_heads: Vec<CanonicalHead>,
    pub head_move_receipts: Vec<CanonicalHeadMove>,
    pub container_manifests: Vec<CanonicalContainerManifest>,
    pub schema_manifest: CanonicalSchemaManifest,
}

impl CanonicalSnapshot {
    /// Validate every section and reference before any reconstruction or storage write.
    pub fn validate(&self) -> Result<()> {
        validation::validate(self)
    }

    /// Deterministic MessagePack, protected by the blake3 artifact envelope.
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let payload = pack(self)?;
        check_size(payload.len().saturating_add(super::HEADER_LEN))?;
        encode_recovery_artifact(CANONICAL_SNAPSHOT_ARTIFACT_TYPE, &payload)
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
            "documents",
            "document_heads",
            "head_move_receipts",
        ] {
            rows.push(CanonicalContainerManifest {
                container_id: name.to_owned(),
                container_kind: "map".to_owned(),
                schema_version: 1,
                source_entity_id: None,
            });
        }
        for doc in &self.doc_snapshots {
            for (name, kind) in [("body", "text"), ("meta", "map")] {
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

/// Captures a quiescent window plus every NOTE document and head receipt in its scope.
/// The caller must stop window writers while taking this off-hot-path snapshot.
pub fn capture_canonical_window(
    vault: &Vault,
    window: &str,
    doc: &LoroDoc,
) -> Result<CanonicalSnapshot> {
    let LoroValue::Map(containers) = doc.get_deep_value() else {
        return Err(invalid("window root"));
    };
    if containers.keys().any(|name| {
        ![
            "entities",
            "edges",
            "tombstones",
            "documents",
            "document_heads",
            "head_move_receipts",
        ]
        .contains(&name.as_str())
    }) {
        return Err(invalid("unknown Layer-1 window container"));
    }
    let mut snapshot = CanonicalSnapshot {
        window: window.to_owned(),
        entity_blobs: Vec::new(),
        base_edges: Vec::new(),
        tombstones: Vec::new(),
        doc_snapshots: Vec::new(),
        document_heads: Vec::new(),
        head_move_receipts: Vec::new(),
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
    };
    for (key, blob) in binary_rows(doc, "entities")? {
        snapshot.entity_blobs.push(CanonicalEntity {
            id: parse_id(&key)?,
            blob,
        });
    }
    for (key, value) in binary_rows(doc, "edges")? {
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
    for (key, value) in binary_rows(doc, "tombstones")? {
        snapshot.tombstones.push(CanonicalTombstone {
            id: parse_id(&key)?,
            deleted_at: crate::deletion::decode_tombstone_value(&value).deleted_at,
            value,
        });
    }
    let txn = vault.store.env.read_txn()?;
    // Pending delete intent is Layer 1 even when a crash preceded CRDT publication.
    let prefix = format!("pt:{window}:");
    for row in vault.store.sync_state.prefix_iter(&txn, &prefix)? {
        let (key, value) = row?;
        let entity = parse_id(&key[prefix.len()..])?;
        if let Some(previous) = snapshot.tombstones.iter_mut().find(|row| row.id == entity) {
            if crate::deletion::decode_tombstone_value(&previous.value).is_hard()
                && !crate::deletion::decode_tombstone_value(&value).is_hard()
            {
                continue;
            }
            previous.value = value.to_vec();
            previous.deleted_at = crate::deletion::decode_tombstone_value(&value).deleted_at;
        } else {
            snapshot.tombstones.push(CanonicalTombstone {
                id: entity,
                deleted_at: crate::deletion::decode_tombstone_value(&value).deleted_at,
                value: value.to_vec(),
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
        let key = format!("dt:{}", id(entity)?.to_hex());
        if let Some(value) = vault.store.sync_state.get(&txn, &key)? {
            if !crate::deletion::decode_tombstone_value(&value).is_hard() {
                return Err(invalid("invalid hard delete marker"));
            }
            snapshot.tombstones.retain(|row| row.id != entity);
            snapshot.tombstones.push(CanonicalTombstone {
                id: entity,
                deleted_at: crate::deletion::decode_tombstone_value(&value).deleted_at,
                value: value.to_vec(),
            });
        }
    }
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
        let shell = vault
            .store
            .entities
            .get(&txn, &tombstone.id)?
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
        for row in vault.store.edges_out.iter(&txn)? {
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
                snapshot.base_edges.push(CanonicalBaseEdge {
                    source,
                    kind: key[16],
                    target,
                    value: value.to_vec(),
                });
            }
        }
    }
    document::capture(vault, &txn, &mut snapshot)?;
    snapshot.entity_blobs.sort_by_key(|row| row.id);
    snapshot
        .base_edges
        .sort_by_key(|row| (row.source, row.kind, row.target));
    snapshot.tombstones.sort_by_key(|row| row.id);
    snapshot.refresh_containers();
    snapshot.validate()?;
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
    for edge in &snapshot.base_edges {
        insert(&doc, "edges", &edge.key()?, &edge.value)?;
    }
    for tombstone in &snapshot.tombstones {
        insert(
            &doc,
            "tombstones",
            &id(tombstone.id)?.to_hex(),
            &tombstone.value,
        )?;
    }
    // Documents are canonical records inside the window; each is reconstructed
    // into its own fresh LoroDoc by the ordinary forward document pass.
    for document in &snapshot.doc_snapshots {
        insert(&doc, "documents", &document.key(), &pack(document)?)?;
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
    doc.commit();
    Ok(doc)
}

pub(super) fn binary_rows(doc: &LoroDoc, name: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut rows = BTreeMap::new();
    let mut failed = false;
    doc.get_map(name).for_each(|key, value| match value {
        ValueOrContainer::Value(LoroValue::Binary(value)) => {
            rows.insert(key.to_owned(), value.to_vec());
        }
        _ => failed = true,
    });
    if failed {
        return Err(invalid("nonbinary Layer-1 carrier"));
    }
    Ok(rows)
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
