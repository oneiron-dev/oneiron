//! Canonical entity-local documents and their bound workflows.

#[cfg(feature = "sync")]
mod materialize;
#[cfg(feature = "sync")]
pub(crate) use materialize::run_in_txn as materialize_recovery_notes_in_txn;
mod workflow;

use loro::LoroDoc;
#[cfg(feature = "sync")]
use loro::{LoroValue, ValueOrContainer};
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
    pub authorship: Vec<crate::note::NoteAuthorship>,
}
impl CanonicalDocument {
    pub(super) fn key(&self) -> String {
        // All callers validate the UUID bytes before they reach storage.
        format!("note-value:v2:{}:{}", hex(self.entity_id), hex(self.head))
    }
    /// Rebuild a new entity document; old insert/delete history is not imported.
    pub fn rebuild(&self) -> Result<LoroDoc> {
        crate::note::recovery::rebuild(id(self.entity_id)?, &self.text, &self.authorship)
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
        let header = crate::batch::EntityMetadataHeader::parse(&entity.blob)
            .ok_or(invalid("entity header"))?;
        if header.entity_type != crate::registry::ENTITY_TYPE_NOTE
            || entity.blob.len() == crate::batch::ENTITY_METADATA_HEADER_LEN
        {
            continue;
        }
        let note = id(entity.id)?;
        crate::note::recovery::guard(vault, txn, note)?;
        let core = crate::note::decode_note_body_using(
            &entity.blob[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            crate::note::NoteKind::wire,
        )?;
        let live = crate::note::recovery::capture(vault, txn, note)?;
        snapshot.doc_snapshots.push(from_doc(
            entity.id,
            entity.id,
            &live,
            *core.author_ref.as_bytes(),
            header.learned_at,
        )?);
        snapshot.document_heads.push(CanonicalHead {
            entity_id: entity.id,
            head: entity.id,
        });
        let prefix = format!("note_proposal_doc:v1:{}:", note.to_hex());
        for row in vault.store.sync_state.prefix_iter(txn, &prefix)? {
            let (key, bytes) = row?;
            let head = parse_id(&key[prefix.len()..])?;
            let doc = LoroDoc::from_snapshot(&bytes).map_err(|_| invalid("proposal document"))?;
            snapshot.doc_snapshots.push(from_doc(
                entity.id,
                head,
                &doc,
                *core.author_ref.as_bytes(),
                header.learned_at,
            )?);
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
    workflow::capture(vault, txn, snapshot, &ids)?;
    Ok(())
}
pub(super) fn from_doc(
    entity_id: [u8; 16],
    head: [u8; 16],
    doc: &LoroDoc,
    birth_actor: [u8; 16],
    birth_at: u64,
) -> Result<CanonicalDocument> {
    let (text, authorship) = crate::note::recovery::values(id(entity_id)?, doc.fork())?;
    if head != entity_id && !authorship.is_empty() {
        return Err(invalid("proposal values cannot carry authority"));
    }
    Ok(CanonicalDocument {
        entity_id,
        head,
        text,
        birth_actor,
        birth_at,
        authorship,
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
        note_forks: Vec::new(),
        note_proposals: Vec::new(),
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
    for (key, bytes) in super::canonical::binary_rows(doc, "note_forks")? {
        let value: crate::note::NoteFork = workflow::decode(&bytes)?;
        if parse_id(&key)? != *value.fork.as_bytes() {
            return Err(invalid("fork carrier key"));
        }
        snapshot.note_forks.push(value);
    }
    for (key, bytes) in super::canonical::binary_rows(doc, "note_proposals")? {
        let value: crate::note::NoteReviewBundle = workflow::decode(&bytes)?;
        if parse_id(&key)? != *value.id.as_bytes() {
            return Err(invalid("proposal carrier key"));
        }
        snapshot.note_proposals.push(value);
    }
    // Only source owners referenced by a document are needed for its validation.
    // Other entity validation remains at the existing forward entity door.
    let mut owners: BTreeSet<_> = snapshot
        .doc_snapshots
        .iter()
        .map(|row| row.entity_id)
        .chain(snapshot.document_heads.iter().map(|row| row.entity_id))
        .chain(snapshot.head_move_receipts.iter().map(|row| row.entity_id))
        .chain(snapshot.note_forks.iter().map(|row| *row.note.as_bytes()))
        .chain(
            snapshot
                .note_proposals
                .iter()
                .flat_map(workflow::bundle_notes),
        )
        .collect();
    if let LoroValue::Map(roots) = doc.get_value()
        && roots.contains_key("documents")
    {
        for (key, blob) in super::canonical::binary_rows(doc, "entities")? {
            if blob.len() > crate::batch::ENTITY_METADATA_HEADER_LEN {
                owners.insert(parse_id(&key)?);
            }
        }
    }
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
    materialize::run(vault, doc, snapshot)
}

pub(super) fn validate_workflows(snapshot: &CanonicalSnapshot) -> Result<()> {
    workflow::validate(snapshot)
}
