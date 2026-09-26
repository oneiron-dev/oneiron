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

#[cfg(feature = "sync")]
use super::canonical::parse_id;
use super::canonical::{CanonicalSnapshot, id, invalid, pack};
use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::note::{NoteFork, NoteLandingReceipt, NoteReviewBundle};
use crate::side_table::{self, HexId, Named, Raw, SideKey, SideTable};

/// Durable head-move (merge/switch/reject) receipt. Key: id16(receipt id).
pub(super) const NOTE_RECEIPT: SideTable<EntityId, NoteLandingReceipt, Named> =
    SideTable::new(&side_table::NOTE_RECEIPT);
/// Durable NOTE fork/proposal-basis row. Key: id16(fork id).
pub(super) const NOTE_FORK: SideTable<EntityId, NoteFork, Named> =
    SideTable::new(&side_table::NOTE_FORK);
/// Durable NOTE proposal bundle. Key: id16(bundle id).
pub(super) const NOTE_PROPOSAL_BUNDLE: SideTable<EntityId, NoteReviewBundle, Named> =
    SideTable::new(&side_table::NOTE_PROPOSAL_BUNDLE);
/// Loro snapshot bytes of a proposal (non-live) NOTE document head. Key:
/// hex32(note) ":" hex32(head).
pub(super) const NOTE_PROPOSAL_DOC: SideTable<DocKey, Vec<u8>, Raw> =
    SideTable::new(&side_table::NOTE_PROPOSAL_DOC);

/// [`NOTE_PROPOSAL_DOC`]'s key: the owning note, then the proposal head, each
/// 32 lower-case hex characters, colon-joined.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DocKey(pub(super) EntityId, pub(super) EntityId);

impl SideKey for DocKey {
    fn encode_into(&self, out: &mut Vec<u8>) {
        HexId(self.0).encode_into(out);
        out.push(b':');
        HexId(self.1).encode_into(out);
    }

    fn decode_key(bytes: &[u8]) -> Option<Self> {
        let (note, rest) = bytes.split_at_checked(32)?;
        let head = rest.strip_prefix(b":")?;
        Some(Self(HexId::decode_key(note)?.0, HexId::decode_key(head)?.0))
    }
}

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
        // The live text plane is its head's document.
        let (live_head, _) = crate::note::documents::head_in(&vault.store, txn, note)?;
        let live = crate::note::recovery::capture(vault, txn, note)?;
        snapshot.doc_snapshots.push(from_doc(
            entity.id,
            *live_head.as_bytes(),
            &live,
            true,
            *core.author_ref.as_bytes(),
            header.learned_at,
        )?);
        snapshot.document_heads.push(CanonicalHead {
            entity_id: entity.id,
            head: *live_head.as_bytes(),
        });
        let note_prefix = [note.to_hex().as_bytes(), b":".as_slice()].concat();
        for row in NOTE_PROPOSAL_DOC.scan_from(&vault.store, txn, &note_prefix)? {
            let (DocKey(_, head), bytes) = row;
            let head = *head.as_bytes();
            if head == *live_head.as_bytes() {
                continue;
            }
            let doc = LoroDoc::from_snapshot(&bytes).map_err(|_| invalid("proposal document"))?;
            snapshot.doc_snapshots.push(from_doc(
                entity.id,
                head,
                &doc,
                false,
                *core.author_ref.as_bytes(),
                header.learned_at,
            )?);
        }
    }
    for (receipt_id, receipt) in NOTE_RECEIPT.scan(&vault.store, txn)? {
        if ids.contains(receipt.note.as_bytes()) {
            if receipt_id != receipt.id {
                return Err(invalid("stored receipt key"));
            }
            let value = CanonicalHeadMove {
                id: *receipt.id.as_bytes(),
                entity_id: *receipt.note.as_bytes(),
                receipt: NOTE_RECEIPT.encode_value(&receipt)?,
            };
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
    live: bool,
    birth_actor: [u8; 16],
    birth_at: u64,
) -> Result<CanonicalDocument> {
    let (text, authorship) = crate::note::recovery::values(id(entity_id)?, doc.fork())?;
    if !live && !authorship.is_empty() {
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
