//! Canonical entity-local documents and their bound head-move receipts.

#[cfg(feature = "sync")]
use loro::ExportMode;
use loro::{LoroDoc, LoroValue, ValueOrContainer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use super::canonical::{CanonicalSnapshot, id, invalid, pack, parse_id};
use crate::Vault;
use crate::error::Result;

/// A format-independent current document snapshot, without retired text or op history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalDocument {
    pub entity_id: [u8; 16],
    pub head: [u8; 16],
    pub text: String,
    pub birth_actor: [u8; 16],
    pub birth_at: u64,
}
impl CanonicalDocument {
    pub(super) fn key(&self) -> String {
        // All callers validate the UUID bytes before they reach storage.
        format!("note_doc:v1:{}:{}", hex(self.entity_id), hex(self.head))
    }
    /// Rebuild a new entity document; old insert/delete history is not imported.
    pub fn rebuild(&self) -> Result<LoroDoc> {
        id(self.entity_id)?;
        id(self.head)?;
        let actor = id(self.birth_actor)?;
        let doc = LoroDoc::new();
        doc.get_map("meta")
            .insert("birth_actor", actor.to_hex())
            .map_err(|_| invalid("document actor"))?;
        doc.get_map("meta")
            .insert("birth_at", self.birth_at.to_string())
            .map_err(|_| invalid("document timestamp"))?;
        doc.get_text("body")
            .insert(0, &self.text)
            .map_err(|_| invalid("document text"))?;
        doc.commit();
        Ok(doc)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalHead {
    pub entity_id: [u8; 16],
    pub head: [u8; 16],
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalHeadMove {
    pub id: [u8; 16],
    pub entity_id: [u8; 16],
    /// Exact Oneiron MessagePack receipt, not a CRDT snapshot.
    pub receipt: Vec<u8>,
}
impl CanonicalHeadMove {
    pub(super) fn decode(&self) -> Result<crate::note::NoteLandingReceipt> {
        let value: crate::note::NoteLandingReceipt =
            rmp_serde::from_slice(&self.receipt).map_err(|_| invalid("head receipt"))?;
        if value.id != id(self.id)?
            || value.note != id(self.entity_id)?
            || pack(&value)? != self.receipt
        {
            return Err(invalid("head receipt binding"));
        }
        Ok(value)
    }
}
fn hex(value: [u8; 16]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
pub(super) fn head_key(entity: [u8; 16]) -> Vec<u8> {
    [b"note_head:v1:".as_slice(), &entity].concat()
}
pub(super) fn receipt_key(receipt: [u8; 16]) -> Vec<u8> {
    [b"note_receipt:v1:".as_slice(), &receipt].concat()
}

pub(super) fn capture(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    snapshot: &mut CanonicalSnapshot,
) -> Result<()> {
    let ids: BTreeSet<_> = snapshot
        .entity_blobs
        .iter()
        .filter(|row| row.blob.len() > crate::batch::ENTITY_METADATA_HEADER_LEN)
        .map(|row| row.id)
        .collect();
    for entity in &snapshot.entity_blobs {
        if !ids.contains(&entity.id) {
            continue;
        }
        let prefix = format!("note_doc:v1:{}:", id(entity.id)?.to_hex());
        for row in vault.store.sync_state.prefix_iter(txn, &prefix)? {
            let (key, bytes) = row?;
            let head = parse_id(&key[prefix.len()..])?;
            let doc = LoroDoc::from_snapshot(&bytes).map_err(|_| invalid("stored document"))?;
            snapshot
                .doc_snapshots
                .push(from_doc(entity.id, head, &doc)?);
        }
        if let Some(head) = vault.store.vault_meta.get(txn, &head_key(entity.id))? {
            snapshot.document_heads.push(CanonicalHead {
                entity_id: entity.id,
                head: head
                    .as_ref()
                    .try_into()
                    .map_err(|_| invalid("stored head"))?,
            });
        }
    }
    for row in vault
        .store
        .vault_meta
        .prefix_iter(txn, b"note_receipt:v1:")?
    {
        let (key, raw) = row?;
        let receipt: crate::note::NoteLandingReceipt =
            rmp_serde::from_slice(&raw).map_err(|_| invalid("stored receipt"))?;
        if ids.contains(receipt.note.as_bytes()) {
            let value = CanonicalHeadMove {
                id: *receipt.id.as_bytes(),
                entity_id: *receipt.note.as_bytes(),
                receipt: raw.to_vec(),
            };
            if key != receipt_key(value.id) {
                return Err(invalid("stored receipt key"));
            }
            value.decode()?;
            snapshot.head_move_receipts.push(value);
        }
    }
    snapshot
        .doc_snapshots
        .sort_by_key(|row| (row.entity_id, row.head));
    snapshot.document_heads.sort_by_key(|row| row.entity_id);
    snapshot.head_move_receipts.sort_by_key(|row| row.id);
    Ok(())
}
pub(super) fn from_doc(
    entity_id: [u8; 16],
    head: [u8; 16],
    doc: &LoroDoc,
) -> Result<CanonicalDocument> {
    // Refuse unknown source containers rather than silently losing future state.
    let LoroValue::Map(root) = doc.get_deep_value() else {
        return Err(invalid("document root"));
    };
    if root.len() != 2 || !root.contains_key("body") || !root.contains_key("meta") {
        return Err(invalid("unknown document container"));
    }
    if !matches!(root.get("body"), Some(LoroValue::String(_)))
        || !matches!(root.get("meta"), Some(LoroValue::Map(_)))
    {
        return Err(invalid("document container kind"));
    }
    let meta = doc.get_map("meta");
    if meta.len() != 2 {
        return Err(invalid("document metadata"));
    }
    let read = |key| match meta.get(key) {
        Some(ValueOrContainer::Value(LoroValue::String(value))) => Ok(value.to_string()),
        _ => Err(invalid("document metadata value")),
    };
    let actor = read("birth_actor")?;
    let at = read("birth_at")?;
    let birth_at: u64 = at
        .parse()
        .map_err(|_| invalid("document birth timestamp"))?;
    if at != birth_at.to_string() {
        return Err(invalid("document timestamp encoding"));
    }
    Ok(CanonicalDocument {
        entity_id,
        head,
        text: doc.get_text("body").to_string(),
        birth_actor: parse_id(&actor)?,
        birth_at,
    })
}

/// Decode and bind document carriers before the forward materializer writes any row.
#[cfg(feature = "sync")]
pub(crate) fn validate_window_documents(doc: &LoroDoc) -> Result<CanonicalSnapshot> {
    let mut snapshot = CanonicalSnapshot {
        window: "2000-01".to_owned(),
        entity_blobs: Vec::new(),
        base_edges: Vec::new(),
        tombstones: Vec::new(),
        doc_snapshots: Vec::new(),
        document_heads: Vec::new(),
        head_move_receipts: Vec::new(),
        container_manifests: Vec::new(),
        schema_manifest: super::CanonicalSchemaManifest {
            oneiron_schema_version: crate::store::STORAGE_ABI_VERSION,
            loro_version: "1.13.9".to_owned(),
            container_schema_version: 1,
            analyzer_manifest_blake3: [0; 32],
        },
    };
    for (key, bytes) in super::canonical::binary_rows(doc, "documents")? {
        let value: CanonicalDocument =
            rmp_serde::from_slice(&bytes).map_err(|_| invalid("document carrier"))?;
        if value.key() != key || pack(&value)? != bytes {
            return Err(invalid("document carrier key"));
        }
        snapshot.doc_snapshots.push(value);
    }
    for (key, bytes) in super::canonical::binary_rows(doc, "document_heads")? {
        let value: CanonicalHead =
            rmp_serde::from_slice(&bytes).map_err(|_| invalid("head carrier"))?;
        if parse_id(&key)? != value.entity_id || pack(&value)? != bytes {
            return Err(invalid("head carrier key"));
        }
        snapshot.document_heads.push(value);
    }
    for (key, bytes) in super::canonical::binary_rows(doc, "head_move_receipts")? {
        let value: CanonicalHeadMove =
            rmp_serde::from_slice(&bytes).map_err(|_| invalid("receipt carrier"))?;
        if parse_id(&key)? != value.id || pack(&value)? != bytes {
            return Err(invalid("receipt carrier key"));
        }
        snapshot.head_move_receipts.push(value);
    }
    // Only source owners referenced by a document are needed for its validation.
    // Other entity validation remains at the existing forward entity door.
    let owners: BTreeSet<_> = snapshot
        .doc_snapshots
        .iter()
        .map(|row| row.entity_id)
        .chain(snapshot.document_heads.iter().map(|row| row.entity_id))
        .chain(snapshot.head_move_receipts.iter().map(|row| row.entity_id))
        .collect();
    for owner in owners {
        let Some(ValueOrContainer::Value(LoroValue::Binary(blob))) =
            doc.get_map("entities").get(&id(owner)?.to_hex())
        else {
            return Err(invalid("document owner absent"));
        };
        snapshot.entity_blobs.push(super::CanonicalEntity {
            id: owner,
            blob: blob.to_vec(),
        });
    }
    snapshot
        .doc_snapshots
        .sort_by_key(|row| (row.entity_id, row.head));
    super::validation::validate_documents(&snapshot)?;
    Ok(snapshot)
}

/// Document pass of standard forward rematerialization. Entity admission has
/// already run; every write is bound to the admitted NOTE and delete gates.
#[cfg(feature = "sync")]
pub(crate) fn materialize_window_documents(
    vault: &Vault,
    doc: &LoroDoc,
    snapshot: &CanonicalSnapshot,
) -> Result<()> {
    // Construct all fresh document exports before taking a write transaction.
    let exports = snapshot
        .doc_snapshots
        .iter()
        .map(|row| {
            Ok((
                row,
                row.rebuild()?
                    .export(ExportMode::Snapshot)
                    .map_err(|_| invalid("document export"))?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    vault.with_write_txn(|txn| {
        let mut admitted = BTreeSet::new();
        for entity in &snapshot.entity_blobs {
            let owner = id(entity.id)?;
            if crate::sync::loro_support::tombstone_map_contains_id(
                &doc.get_map("tombstones"),
                &owner,
            ) || vault.local_hard_delete_marker_exists_in_txn(txn, &owner)?
            {
                continue;
            }
            let Some(raw) = vault.store.entities.get(txn, owner.as_bytes())? else {
                continue;
            };
            // A quarantined/divergent core cannot lend authority to document bytes.
            if raw.as_ref() != entity.blob.as_slice() {
                return Err(invalid("document core was not admitted"));
            }
            admitted.insert(entity.id);
        }
        for (row, bytes) in &exports {
            if !admitted.contains(&row.entity_id) {
                continue;
            }
            let same = vault
                .store
                .sync_state
                .get(txn, &row.key())?
                .is_some_and(|current| {
                    LoroDoc::from_snapshot(&current)
                        .ok()
                        .and_then(|old| from_doc(row.entity_id, row.head, &old).ok())
                        .as_ref()
                        == Some(*row)
                });
            if !same {
                vault.store.sync_state.put(txn, &row.key(), bytes)?;
            }
        }
        for head in &snapshot.document_heads {
            if !admitted.contains(&head.entity_id) {
                continue;
            }
            vault
                .store
                .vault_meta
                .put(txn, &head_key(head.entity_id), &head.head)?;
            let text = &snapshot
                .doc_snapshots
                .iter()
                .find(|row| row.entity_id == head.entity_id && row.head == head.head)
                .ok_or(invalid("missing head document"))?
                .text;
            vault
                .batch_in()
                .text(&id(head.entity_id)?, &[("markdown", text.as_str())])
                .apply(txn)?;
        }
        for receipt in &snapshot.head_move_receipts {
            if !admitted.contains(&receipt.entity_id) {
                continue;
            }
            let key = receipt_key(receipt.id);
            if let Some(previous) = vault.store.vault_meta.get(txn, &key)?
                && previous.as_ref() != receipt.receipt.as_slice()
            {
                return Err(invalid("immutable head receipt divergence"));
            }
            vault.store.vault_meta.put(txn, &key, &receipt.receipt)?;
        }
        Ok(())
    })
}
