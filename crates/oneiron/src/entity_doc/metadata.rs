//! Editable record fields live in the owning document's meta map.

use std::collections::BTreeMap;

use loro::LoroDoc;
use rmpv::Value;

use super::{DocAuthorization, EntityDoc, TextField, invalid, storage};
use crate::sync::loro_support::{map_get_bytes, map_insert_bytes};
use crate::{EntityId, Result, Vault, WriteActor};

/// One attributed metadata mutation. `None` removes the field.
#[derive(Debug, Clone, PartialEq)]
pub struct MetadataEdit {
    pub field: String,
    pub value: Option<Value>,
}

pub(crate) use crate::ports::{is_metadata_field, is_text_field, validate_metadata};

pub(super) fn encode_value(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, value)
        .map_err(|_| invalid("document metadata encoding"))?;
    Ok(bytes)
}

pub(crate) fn decode_metadata_value(bytes: &[u8]) -> Result<Value> {
    let mut cursor = bytes;
    let value =
        rmpv::decode::read_value(&mut cursor).map_err(|_| invalid("document metadata encoding"))?;
    if !cursor.is_empty() {
        return Err(invalid("trailing document metadata bytes"));
    }
    Ok(value)
}

const RECORD_FIELDS: &str = "entity_doc_record_fields";

impl EntityDoc {
    pub(super) fn record_fields(&self) -> Result<Vec<String>> {
        map_get_bytes(&self.doc.get_map("meta"), RECORD_FIELDS)
            .map(|bytes| storage::decode(&bytes))
            .transpose()
            .map(Option::unwrap_or_default)
    }

    pub(super) fn set_record_fields(doc: &LoroDoc, fields: &[String]) -> Result<()> {
        let bytes =
            rmp_serde::to_vec(fields).map_err(|_| invalid("document record fields encoding"))?;
        map_insert_bytes(&doc.get_map("meta"), RECORD_FIELDS, &bytes)
    }

    /// Editable fields at this document version, separate from birth provenance.
    pub fn metadata(&self) -> Result<BTreeMap<String, Value>> {
        self.metadata_bytes()?
            .into_iter()
            .map(|(field, bytes)| Ok((field, decode_metadata_value(&bytes)?)))
            .collect()
    }

    pub(super) fn metadata_bytes(&self) -> Result<BTreeMap<String, Vec<u8>>> {
        let map = self.doc.get_map("meta");
        let mut fields = BTreeMap::new();
        let mut failure = None;
        map.for_each(|field, _| {
            if !is_metadata_field(field) || failure.is_some() {
                return;
            }
            match map_get_bytes(&map, field)
                .ok_or(invalid("document metadata must be encoded values"))
                .and_then(|bytes| {
                    validate_metadata(field, &decode_metadata_value(&bytes)?)?;
                    Ok(bytes)
                }) {
                Ok(bytes) => {
                    fields.insert(field.to_owned(), bytes);
                }
                Err(error) => failure = Some(error),
            }
        });
        match failure {
            Some(error) => Err(error),
            None => Ok(fields),
        }
    }

    pub(super) fn replace_metadata(
        doc: &LoroDoc,
        fields: &BTreeMap<String, Vec<u8>>,
    ) -> Result<()> {
        let map = doc.get_map("meta");
        let mut old = Vec::new();
        map.for_each(|field, _| {
            if is_metadata_field(field) && !fields.contains_key(field) {
                old.push(field.to_owned());
            }
        });
        for field in old {
            map.delete(&field)
                .map_err(|_| invalid("document metadata removal"))?;
        }
        for (field, bytes) in fields {
            validate_metadata(field, &decode_metadata_value(bytes)?)?;
            map_insert_bytes(&map, field, bytes)?;
        }
        Ok(())
    }
}

impl Vault {
    /// Edits metadata on the same document, under the same authority and history
    /// as body edits. The immutable record is never rewritten.
    pub fn edit_entity_metadata(
        &self,
        entity: &EntityId,
        edits: &[MetadataEdit],
        actor: WriteActor,
        authorization: &DocAuthorization<'_>,
        at: u64,
    ) -> Result<Vec<u8>> {
        if edits.is_empty() || edits.len() > 50 {
            return Err(invalid("metadata edit requires 1 to 50 operations"));
        }
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        let frontier = self.with_write_txn_grouped(|txn| {
            super::forks::authorize(self, txn, authorization, entity, actor)?;
            let mut head = storage::head(&self.store, txn, entity)?;
            let doc = storage::load(&self.store, txn, &head)?;
            let before = doc.doc.oplog_vv();
            doc.doc
                .set_peer_id(LoroDoc::new().peer_id())
                .map_err(|_| invalid("document peer rotation"))?;
            super::forks::bind_actor(self, txn, &doc, actor, at)?;
            let map = doc.doc.get_map("meta");
            for edit in edits {
                if !is_metadata_field(&edit.field)
                    || head.field == TextField::MapField(edit.field.clone())
                {
                    return Err(invalid("field is not document metadata"));
                }
                match &edit.value {
                    Some(value) => {
                        validate_metadata(&edit.field, value)?;
                        map_insert_bytes(&map, &edit.field, &encode_value(value)?)?;
                    }
                    None => {
                        map.delete(&edit.field)
                            .map_err(|_| invalid("document metadata removal"))?;
                    }
                }
            }
            super::document::stamp(&doc.doc, actor, at, "metadata")?;
            storage::persist(self, txn, entity, &mut head, &doc, Some(&before))?;
            Ok(doc.frontier())
        })?;
        registry.remove(entity);
        Ok(frontier)
    }
}
