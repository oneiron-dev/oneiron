//! Source facts for a SKILL record and its native document in one window.
//!
//! This payload is data, not admission. Its decoder proves the row/document
//! binding only. The selected-window ingest door must still run ordinary
//! record admission before installing either view in its parent writer.

use heed::RoTxn;
use serde::{Deserialize, Serialize};

use super::carried::{CarriedDocument, SwitchedFrom};
use super::document::decode_frontier;
use super::storage::{self, ENTITY_DOC_HEAD};
use super::{EntityDoc, ForkStatus, TextField, invalid};
use crate::batch::{ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::error::Result;
use crate::ports::EntityStoreRead;
use crate::side_table::HexId;
use crate::store::Store;
use crate::{EntityId, registry::ENTITY_TYPE_SKILL};

/// A native document's source identity, bound to the exact stored record.
/// Sender-local generation/update counters are deliberately not carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CarriedRecordDocument {
    native: CarriedDocument,
    field: TextField,
    row_digest: [u8; 32],
    /// Historical source evidence, not a receiver-local document birth.
    source_birth_frontier: Option<Vec<u8>>,
    /// The permanent first-Candidate byte hash, not a hash of today's view.
    refinement_origin: Option<[u8; 32]>,
}

impl CarriedRecordDocument {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(self).map_err(|_| invalid("record document encoding"))
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let carried: Self = storage::decode(bytes)?;
        carried.entity()?;
        if carried.encode()? != bytes {
            return Err(invalid("record document has another spelling"));
        }
        Ok(carried)
    }

    pub(crate) fn entity(&self) -> Result<EntityId> {
        let entity = self
            .native
            .message()
            .ok_or(invalid("record document identity"))?;
        match &self.field {
            TextField::MapField(field) if super::metadata::is_text_field(field) => {}
            _ => return Err(invalid("record document field")),
        }
        if let Some(frontier) = &self.source_birth_frontier {
            decode_frontier(frontier)?;
        }
        Ok(entity)
    }

    pub(crate) fn native(&self) -> &CarriedDocument {
        &self.native
    }

    pub(crate) fn field(&self) -> &TextField {
        &self.field
    }

    pub(crate) fn source_birth_frontier(&self) -> Option<&[u8]> {
        self.source_birth_frontier.as_deref()
    }

    pub(crate) fn refinement_origin(&self) -> Option<&[u8; 32]> {
        self.refinement_origin.as_ref()
    }

    /// Reassemble and bind data without treating it as permission to land.
    /// No receiver head, body, birth, receipt or index is written here.
    pub(crate) fn document(&self, raw: &[u8], snapshot: &[u8]) -> Result<EntityDoc> {
        let entity = self.entity()?;
        if EntityMetadataHeader::parse(raw)
            .is_none_or(|header| header.entity_type != ENTITY_TYPE_SKILL)
            || self.row_digest != *blake3::hash(raw).as_bytes()
        {
            return Err(invalid("record document names another row"));
        }
        let body = &raw[ENTITY_METADATA_HEADER_LEN..];
        let mut cursor = body;
        let value = rmpv::decode::read_value(&mut cursor)
            .map_err(|_| invalid("record document pointer"))?;
        let rmpv::Value::Map(fields) = value else {
            return Err(invalid("record document pointer"));
        };
        let pointers: Vec<_> = fields
            .iter()
            .filter(|(key, _)| key.as_str() == Some("entity_doc_ref"))
            .collect();
        if !cursor.is_empty()
            || pointers.len() != 1
            || pointers[0].1.as_str() != Some(self.native.document.as_str())
        {
            return Err(invalid("record document names another pointer"));
        }
        let doc = EntityDoc::from_snapshot(snapshot)?;
        let floor = if doc.doc.is_shallow() {
            doc.doc.shallow_since_vv().to_vv().encode()
        } else {
            Vec::new()
        };
        if doc.birth().entity != entity.to_hex()
            || self.native.version != doc.doc.oplog_vv().encode()
            || self.native.shallow != floor
        {
            return Err(invalid("record document snapshot differs from its head"));
        }
        // The strict native record codec checks the complete logical view,
        // not the pointer bytes which the original row must retain.
        let logical = storage::body_with_document(&self.field, body, &doc)?;
        crate::write_envelope::skill_record::decode_skill_record(&logical)?;
        Ok(doc)
    }
}

/// Capture the actual stored row, head, document and permanent origin in one
/// source snapshot. A window with another row must mirror that row first.
/// The returned source birth remains historical evidence on another device.
pub(crate) fn export_skill_record_document_in_txn(
    store: &Store,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    selected_raw: &[u8],
) -> Result<Option<(CarriedRecordDocument, Vec<u8>)>> {
    if EntityMetadataHeader::parse(selected_raw)
        .is_none_or(|header| header.entity_type != ENTITY_TYPE_SKILL)
    {
        return Ok(None);
    }
    let Some(raw) = store.port_entity_raw(txn, entity)? else {
        return Ok(None);
    };
    if raw.as_ref() != selected_raw {
        return Ok(None);
    }
    let Some(head) = ENTITY_DOC_HEAD.get(store, txn, &HexId(*entity))? else {
        return Ok(None);
    };
    storage::require_live(store, txn, entity)?;
    if head.entity != entity.to_hex() {
        return Err(invalid("record document owner mismatch"));
    }
    let doc = storage::load(store, txn, &head)?;
    let switched = super::forks::ENTITY_DOC_FORK
        .get(store, txn, &head.document)?
        .filter(|fork| fork.status == ForkStatus::Switched && fork.entity == head.entity)
        .map(|fork| SwitchedFrom {
            document: fork.parent_document,
            base: fork.base,
        });
    let carried = CarriedRecordDocument {
        native: CarriedDocument {
            entity: head.entity,
            document: head.document,
            incarnation: head.incarnation,
            version: doc.doc.oplog_vv().encode(),
            shallow: if doc.doc.is_shallow() {
                doc.doc.shallow_since_vv().to_vv().encode()
            } else {
                Vec::new()
            },
            switched,
        },
        field: head.field,
        row_digest: *blake3::hash(selected_raw).as_bytes(),
        source_birth_frontier: head.birth_frontier,
        refinement_origin: crate::store::skill_refinement_origin::SKILL_ORIGIN
            .get(store, txn, entity)?,
    };
    let snapshot = doc.export_snapshot()?;
    carried.document(selected_raw, &snapshot)?;
    Ok(Some((carried, snapshot)))
}
