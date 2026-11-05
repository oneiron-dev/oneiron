//! Editable record fields live in the owning document's meta map.

use std::collections::BTreeMap;

use loro::LoroDoc;
use rmpv::Value;

use super::document::{map_get_bytes, map_insert_bytes};
use super::{DocAuthorization, EntityDoc, TextField, invalid, storage};
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
        // No count bounds the edit: every operation lands as one (FIX 9845).
        if edits.is_empty() {
            return Err(invalid("metadata edit requires an operation"));
        }
        let mut registry = self
            .entity_docs
            .lock()
            .map_err(|_| invalid("document registry poisoned"))?;
        let frontier = self.with_write_txn_grouped(|txn| {
            super::forks::authorize(self, txn, authorization, entity, actor)?;
            // A shared vault's role and record scope, in the committing writer
            // (FIX 9846).
            self.authorize_shared_content_write_in_txn(txn, *entity, &actor)?;
            let mut head = storage::head(&self.store, txn, entity)?;
            let doc = storage::load(&self.store, txn, &head)?;
            let before = doc.doc.oplog_vv();
            doc.doc
                .set_peer_id(LoroDoc::new().peer_id())
                .map_err(|_| invalid("document peer rotation"))?;
            super::forks::bind_actor(self, txn, &doc, actor, at)?;
            // The edit's commit names the actor's stamp token (FIX 10930).
            let stamp = crate::provenance::actor_stamp_in_txn(self, txn, actor)?;
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
            super::document::stamp(&doc.doc, stamp, at, "metadata")?;
            storage::persist(self, txn, entity, &mut head, &doc, Some(&before))?;
            Ok(doc.frontier())
        })?;
        registry.remove(entity);
        Ok(frontier)
    }
}

/// Checks common record metadata at its current state, shallow floor and
/// every retained raw mutation, including inserts hidden by later writes.
/// Other META keys, native extension roots and body/source admission
/// remain their owners'. This is not a complete document schema check.
pub(super) fn require_retained_record_metadata(doc: &EntityDoc, field: &TextField) -> Result<()> {
    require_record_metadata_state(&doc.doc, field, doc.birth())?;
    if doc.doc.is_shallow() {
        // This state-only export is a read of the actual retained floor,
        // never a replacement for the candidate's full retained snapshot.
        // A generic text prefix need not already have a native birth.
        let floor = doc.doc.shallow_since_frontiers();
        let bytes = doc
            .doc
            .export(loro::ExportMode::state_only(Some(&floor)))
            .map_err(|_| invalid("record metadata floor export"))?;
        let at_floor = LoroDoc::from_snapshot(&bytes)
            .map_err(|_| invalid("record metadata floor snapshot"))?;
        require_record_metadata_state(&at_floor, field, doc.birth())?;
    }
    let history = doc.doc.export_json_updates_without_peer_compression(
        &doc.doc.shallow_since_vv().to_vv(),
        &doc.doc.oplog_vv(),
    );
    for change in history.changes {
        for operation in change.ops {
            let loro::ContainerID::Root {
                name,
                container_type,
            } = operation.container
            else {
                continue;
            };
            if name.as_str() != super::document::META {
                continue;
            }
            if container_type != loro::ContainerType::Map {
                return Err(invalid("record metadata container"));
            }
            match operation.content {
                loro::JsonOpContent::Map(loro::JsonMapOp::Insert { key, value }) => {
                    require_record_metadata_value(&key, &value, field, doc.birth())?;
                }
                loro::JsonOpContent::Map(loro::JsonMapOp::Delete { key })
                    if !is_common_record_metadata_key(&key)
                        || (is_metadata_field(&key) && !is_record_body_field(field, &key)) => {}
                _ => return Err(invalid("record metadata operation")),
            }
        }
    }
    Ok(())
}

fn require_record_metadata_state(
    doc: &LoroDoc,
    field: &TextField,
    birth: &super::Birth,
) -> Result<()> {
    let map = doc.get_map(super::document::META);
    let mut failure = None;
    map.for_each(|key, _| {
        if failure.is_some() || !is_common_record_metadata_key(key) {
            return;
        }
        let result = match map.get(key) {
            Some(loro::ValueOrContainer::Value(value)) => {
                require_record_metadata_value(key, &value, field, birth)
            }
            _ => Err(invalid("record metadata value")),
        };
        if let Err(error) = result {
            failure = Some(error);
        }
    });
    failure.map_or(Ok(()), Err)
}

fn require_record_metadata_value(
    key: &str,
    value: &loro::LoroValue,
    field: &TextField,
    birth: &super::Birth,
) -> Result<()> {
    if !is_common_record_metadata_key(key) {
        return Ok(());
    }
    let loro::LoroValue::Binary(bytes) = value else {
        return Err(invalid("record metadata value"));
    };
    match key {
        super::document::BIRTH => {
            let stored = super::Birth::decode(bytes.as_slice())?;
            if stored.entity != birth.entity
                || stored.at != birth.at
                || stored.encode()?.as_slice() != bytes.as_slice()
            {
                return Err(invalid("record metadata retained birth"));
            }
        }
        RECORD_FIELDS => {
            let fields: Vec<String> = storage::decode(bytes.as_slice())?;
            if fields
                .iter()
                .any(|key| !is_metadata_field(key) || is_record_body_field(field, key))
            {
                return Err(invalid("record metadata record fields"));
            }
        }
        _ if is_metadata_field(key) && !is_record_body_field(field, key) => {
            validate_metadata(key, &decode_metadata_value(bytes.as_slice())?)?;
        }
        _ => return Err(invalid("record metadata field")),
    }
    Ok(())
}

fn is_record_body_field(field: &TextField, key: &str) -> bool {
    matches!(field, TextField::MapField(body) if body == key)
}

fn is_common_record_metadata_key(key: &str) -> bool {
    matches!(key, super::document::BIRTH | RECORD_FIELDS) || is_metadata_field(key)
}
