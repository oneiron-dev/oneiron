//! Transactional entity-document storage and row-pointer migration.

use super::{DocAuthorization, EntityDoc, invalid};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::{Error, Result};
use crate::ports::{
    DocumentRow, DocumentRowStore, DocumentSlot, EntityStoreMaintenance, UpdateSeq,
};
use crate::side_table::{self, HexId, Named, SideTable};
use crate::store::Store;
use crate::vault::{LiveEntityRow, live_entity_row_in_txn};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Vault};
use heed::{RoTxn, RwTxn};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Location of the original editable text. Other MessagePack fields stay intact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TextField {
    /// A legacy body containing only UTF-8 text.
    Utf8Body,
    /// A named UTF-8 string in a MessagePack map.
    MapField(String),
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Head {
    pub entity: String,
    pub incarnation: String,
    pub document: String,
    pub field: TextField,
    pub generation: u64,
    pub pending: u64,
}

/// Pointer from an entity to its owning document, plus generation/pending
/// counters.
pub(super) const ENTITY_DOC_HEAD: SideTable<HexId, Head, Named> =
    SideTable::new(&side_table::ENTITY_DOC_HEAD);

pub(super) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let mut reader = std::io::Cursor::new(bytes);
    let value = T::deserialize(&mut rmp_serde::Deserializer::new(&mut reader))
        .map_err(|_| Error::CorruptedIndex("entity document row"))?;
    if usize::try_from(reader.position()).ok() != Some(bytes.len()) {
        return Err(Error::CorruptedIndex("trailing entity document row bytes"));
    }
    Ok(value)
}

pub(super) fn require_live(store: &Store, txn: &RoTxn<'_>, entity: &EntityId) -> Result<()> {
    match live_entity_row_in_txn(store, txn, entity)? {
        LiveEntityRow::Live { entity_type, .. }
            if entity_type != crate::registry::ENTITY_TYPE_SECRET_CUSTODY =>
        {
            Ok(())
        }
        _ => Err(Error::EntityNotFound),
    }
}

pub(super) fn head(store: &Store, txn: &RoTxn<'_>, entity: &EntityId) -> Result<Head> {
    require_live(store, txn, entity)?;
    let h = ENTITY_DOC_HEAD
        .get(store, txn, &HexId(*entity))?
        .ok_or(Error::EntityNotFound)?;
    if h.entity != entity.to_hex() {
        return Err(Error::CorruptedIndex("document head entity mismatch"));
    }
    Ok(h)
}

pub(super) fn load(store: &Store, txn: &RoTxn<'_>, h: &Head) -> Result<EntityDoc> {
    let slot = DocumentSlot::from_hex(&h.document)?;
    let bytes = store
        .port_document_row(txn, slot, DocumentRow::Snapshot)?
        .ok_or(Error::CorruptedIndex("entity document snapshot missing"))?;
    let doc = EntityDoc::from_snapshot(&bytes)?;
    if doc.birth().entity != h.entity {
        return Err(Error::CorruptedIndex("document birth entity mismatch"));
    }
    // Strictly replay snapshot then updates. Fixed-width keys preserve order.
    let mut count = 0_u64;
    for update in store.port_document_updates(txn, slot)? {
        let status = doc
            .doc
            .import(&update.bytes)
            .map_err(|_| Error::CorruptedIndex("entity document update"))?;
        if status.pending.is_some() {
            return Err(Error::CorruptedIndex("entity document update dependencies"));
        }
        count += 1;
    }
    if count != h.pending {
        return Err(Error::CorruptedIndex("entity document update sequence"));
    }
    Ok(doc)
}

pub(super) fn persist(
    vault: &Vault,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    h: &mut Head,
    doc: &EntityDoc,
    before: Option<&loro::VersionVector>,
) -> Result<()> {
    let store = &vault.store;
    crate::batch::secret_scan::scan_metadata_field(&doc.text())?;
    vault.ensure_text_index_trusted()?;
    crate::vault::ensure_text_index_manifest_matches_wtxn(store, txn, &vault.analyzer)?;
    crate::bm25::index_text(
        store,
        txn,
        &vault.analyzer,
        entity,
        &[(
            match &h.field {
                TextField::Utf8Body => "body".to_owned(),
                TextField::MapField(field) => field.clone(),
            },
            doc.text(),
        )],
    )?;
    h.generation = h
        .generation
        .checked_add(1)
        .ok_or(invalid("document generation overflow"))?;
    let slot = DocumentSlot::from_hex(&h.document)?;
    if let Some(before) = before.filter(|_| h.pending < 31) {
        let bytes = doc
            .doc
            .export(loro::ExportMode::updates(before))
            .map_err(|_| invalid("document update export"))?;
        store.port_document_update_put(txn, slot, UpdateSeq::Generation(h.generation), &bytes)?;
        h.pending += 1;
    } else {
        store.port_document_snapshot_put(txn, slot, &doc.export_snapshot()?)?;
        store.port_document_updates_delete(txn, slot)?;
        h.pending = 0;
    }
    store.port_document_state_vector_put(txn, slot, &doc.doc.oplog_vv().encode())?;
    ENTITY_DOC_HEAD.put(store, txn, &HexId(*entity), h)?;
    Ok(())
}

impl Vault {
    /// Moves original text into its first CRDT commit and replaces it with a
    /// document pointer atomically. The row's original timestamp is authoritative.
    /// Birth attribution must identify the original writer, not the migrator.
    pub fn migrate_entity_text(
        &self,
        entity: &EntityId,
        field: &TextField,
        birth_actor: WriteActor,
        authorization: &DocAuthorization<'_>,
    ) -> Result<()> {
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        self.with_write_txn(|txn| {
            super::forks::validate_actor(self, txn, birth_actor)?;
            let authorizer = match authorization {
                DocAuthorization::Owner(owner) => {
                    WriteActor::new(owner.actor(), crate::edge::EdgeActorClass::Human)
                }
                _ => birth_actor,
            };
            super::forks::authorize(self, txn, authorization, entity, authorizer)?;
            require_live(&self.store, txn, entity)?;
            if ENTITY_DOC_HEAD.contains(&self.store, txn, &HexId(*entity))? {
                return Err(invalid("entity already owns a document"));
            }
            let raw = self
                .store
                .entities
                .get(txn, entity.as_bytes())?
                .ok_or(Error::EntityNotFound)?
                .to_vec();
            let header =
                EntityMetadataHeader::parse(&raw).ok_or(Error::CorruptedIndex("entity header"))?;
            // System/secret and CLAIM codecs carry their own immutable payload laws.
            // They cannot be turned into arbitrary text by this migration door.
            if !crate::registry::is_structural_kind(header.entity_type) {
                return Err(invalid("this record kind does not carry editable text"));
            }
            let body = &raw[ENTITY_METADATA_HEADER_LEN..];
            if let TextField::MapField(name) = field
                && !["body", "text", "txt", "content", "markdown", "title"].contains(&name.as_str())
            {
                return Err(invalid("only text fields can move to the document plane"));
            }
            if header.entity_type == crate::registry::ENTITY_TYPE_MESSAGE {
                if *field != TextField::MapField("content".to_owned()) {
                    return Err(invalid("MESSAGE document edits only content"));
                }
                crate::gate::validate_canonical_witness_message_body(body)?;
            }
            if header.entity_type == crate::registry::ENTITY_TYPE_NOTE {
                let original = crate::note::decode_note_body(body)?;
                if original.author_ref != birth_actor.entity_ref()
                    || *field != TextField::MapField("markdown".to_owned())
                {
                    return Err(invalid(
                        "note migration must preserve its original author and markdown field",
                    ));
                }
            }
            let (initial, pointer) = replace_text(body, field, &entity.to_hex())?;
            crate::origin::lfs::guard_lfs_asset_put(
                &self.store,
                txn,
                entity,
                header.entity_type,
                &pointer,
            )?;
            let doc = EntityDoc::open(*entity, &initial, birth_actor, header.occurred_start)?;
            super::forks::bind_actor(self, txn, &doc, birth_actor, header.occurred_start)?;
            // The immutable envelope, type/time indexes and other body fields do
            // not change. The only replaced bytes are text -> head pointer.
            self.store
                .port_entity_document_pointer_put(txn, entity, &pointer)?;
            let mut h = Head {
                entity: entity.to_hex(),
                incarnation: EntityId::now().to_hex(),
                document: entity.to_hex(),
                field: field.clone(),
                generation: 0,
                pending: 0,
            };
            persist(self, txn, entity, &mut h, &doc, None)
        })?;
        registry.remove(entity);
        Ok(())
    }
}

fn replace_text(body: &[u8], field: &TextField, doc: &str) -> Result<(String, Vec<u8>)> {
    let (text, mut fields) = match field {
        TextField::Utf8Body => (
            std::str::from_utf8(body)
                .map_err(|_| invalid("body is not UTF-8 text"))?
                .to_owned(),
            Vec::new(),
        ),
        TextField::MapField(key) => {
            if key == "entity_doc_ref" {
                return Err(invalid("reserved document pointer field"));
            }
            let mut cursor = std::io::Cursor::new(body);
            let value = rmpv::decode::read_value(&mut cursor)
                .map_err(|_| invalid("body is not a MessagePack map"))?;
            if cursor.position() != body.len() as u64 {
                return Err(invalid("trailing bytes after MessagePack body"));
            }
            let rmpv::Value::Map(mut fields) = value else {
                return Err(invalid("body is not a MessagePack map"));
            };
            let matches: Vec<usize> = fields
                .iter()
                .enumerate()
                .filter_map(|(i, (k, _))| (k.as_str() == Some(key)).then_some(i))
                .collect();
            if matches.len() != 1 {
                return Err(invalid("text field missing or duplicated"));
            }
            let (_, value) = fields.remove(matches[0]);
            (
                value
                    .as_str()
                    .ok_or(invalid("text field is not a string"))?
                    .to_owned(),
                fields,
            )
        }
    };
    if fields
        .iter()
        .any(|(k, _)| k.as_str() == Some("entity_doc_ref"))
    {
        return Err(invalid("record already carries a text pointer"));
    }
    fields.push((rmpv::Value::from("entity_doc_ref"), rmpv::Value::from(doc)));
    let mut out = Vec::new();
    rmpv::encode::write_value(&mut out, &rmpv::Value::Map(fields))
        .map_err(|_| invalid("document pointer encoding"))?;
    Ok((text, out))
}

/// Batch/replay chokepoint: an active text plane cannot be bypassed by a blob put.
pub(crate) fn guard_record_put(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    data: &[u8],
) -> Result<()> {
    if ENTITY_DOC_HEAD.contains(store, txn, &HexId(*entity))? {
        let old = store
            .entities
            .get(txn, entity.as_bytes())?
            .ok_or(Error::EntityNotFound)?;
        if old.get(ENTITY_METADATA_HEADER_LEN..) != Some(data) {
            return Err(invalid(
                "editable text must be changed through its entity document",
            ));
        }
    }
    Ok(())
}

/// Destructive deletion hook; archive never calls it. Removes every content
/// carrier for the entity, including pending updates, retained forks and quotes.
pub(crate) fn erase_in_txn(store: &Store, txn: &mut RwTxn<'_>, entity: &EntityId) -> Result<()> {
    if let Some(h) = ENTITY_DOC_HEAD.get(store, txn, &HexId(*entity))? {
        for doc in [entity.to_hex(), h.document] {
            drop_document(store, txn, &doc)?;
        }
    }
    super::forks::erase_forks(store, txn, entity)?;
    super::pins::ENTITY_DOC_PIN.delete_from(
        store,
        txn,
        format!("{}:", entity.to_hex()).as_bytes(),
    )?;
    ENTITY_DOC_HEAD.delete(store, txn, &HexId(*entity))?;
    Ok(())
}

pub(super) fn move_pointer(
    store: &Store,
    txn: &mut RwTxn<'_>,
    entity: &EntityId,
    document: &str,
) -> Result<()> {
    let raw = store
        .entities
        .get(txn, entity.as_bytes())?
        .ok_or(Error::EntityNotFound)?;
    let value = rmpv::decode::read_value(&mut std::io::Cursor::new(
        &raw[ENTITY_METADATA_HEADER_LEN..],
    ))
    .map_err(|_| Error::CorruptedIndex("document pointer row"))?;
    let rmpv::Value::Map(mut fields) = value else {
        return Err(Error::CorruptedIndex("document pointer row"));
    };
    let slot = fields
        .iter_mut()
        .find(|(key, _)| key.as_str() == Some("entity_doc_ref"))
        .ok_or(Error::CorruptedIndex("document pointer missing"))?;
    slot.1 = rmpv::Value::from(document);
    let mut body = Vec::new();
    rmpv::encode::write_value(&mut body, &rmpv::Value::Map(fields))
        .map_err(|_| invalid("document pointer encoding"))?;
    store.port_entity_document_pointer_put(txn, entity, &body)
}

/// Removes a document's snapshot, state vectors and pending updates.
pub(super) fn drop_document(store: &Store, txn: &mut RwTxn<'_>, document: &str) -> Result<()> {
    let slot = DocumentSlot::from_hex(document)?;
    let rows = [
        DocumentRow::Snapshot,
        DocumentRow::StateVector,
        DocumentRow::ShallowSince,
    ];
    store.port_document_rows_delete(txn, slot, &rows)?;
    store.port_document_updates_delete(txn, slot)
}

/// A migrated record keeps the EntityDoc codec, even when it is a NOTE.
/// Errors and malformed heads must not fall through to another document codec.
pub(crate) fn has_record_head(store: &Store, txn: &RoTxn<'_>, entity: &EntityId) -> Result<bool> {
    ENTITY_DOC_HEAD.contains(store, txn, &HexId(*entity))
}

/// Read-only view for existing typed record readers; the durable row retains
/// only the pointer and immutable fields, never a second copy of the text.
pub(crate) fn resolve_record_body(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    body: &[u8],
) -> Result<Vec<u8>> {
    let Some(h) = ENTITY_DOC_HEAD.get(store, txn, &HexId(*entity))? else {
        return Ok(body.to_vec());
    };
    require_live(store, txn, entity)?;
    let text = load(store, txn, &h)?.text();
    match h.field {
        TextField::Utf8Body => Ok(text.into_bytes()),
        TextField::MapField(field) => {
            let value = rmpv::decode::read_value(&mut std::io::Cursor::new(body))
                .map_err(|_| Error::CorruptedIndex("document pointer row"))?;
            let rmpv::Value::Map(mut fields) = value else {
                return Err(Error::CorruptedIndex("document pointer row"));
            };
            fields.retain(|(key, _)| key.as_str() != Some("entity_doc_ref"));
            fields.push((rmpv::Value::from(field), rmpv::Value::from(text)));
            let mut out = Vec::new();
            rmpv::encode::write_value(&mut out, &rmpv::Value::Map(fields))
                .map_err(|_| invalid("document view encoding"))?;
            Ok(out)
        }
    }
}
