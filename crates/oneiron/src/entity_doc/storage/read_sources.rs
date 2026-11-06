//! Opt-in observation of original head/snapshot/update reads. No authority is inferred here.

use super::{ENTITY_DOC_HEAD, EntityDoc, Head, body_with_document, require_live};
use crate::EntityId;
use crate::error::{Error, Result};
use crate::ports::{
    DocumentRead, DocumentReadObserver, DocumentRow, DocumentRowStore, DocumentSlot,
};
use crate::side_table::HexId;
use heed::RoTxn;

pub(super) fn load(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    h: &Head,
    mut observe: Option<&mut DocumentReadObserver<'_>>,
) -> Result<EntityDoc> {
    let slot = DocumentSlot::from_hex(&h.document)?;
    let bytes = match observe.as_mut() {
        Some(observe) => store.port_document_row_observed(
            txn,
            slot,
            DocumentRow::Snapshot,
            Some(&mut **observe),
        )?,
        None => store.port_document_row(txn, slot, DocumentRow::Snapshot)?,
    }
    .ok_or(Error::CorruptedIndex("entity document snapshot missing"))?;
    let doc = EntityDoc::from_snapshot(&bytes)?;
    if doc.birth().entity != h.entity {
        return Err(Error::CorruptedIndex("document birth entity mismatch"));
    }
    // Strictly replay snapshot then updates. Fixed-width keys preserve order.
    let mut count = 0_u64;
    let updates = match observe.as_mut() {
        Some(observe) => store.port_document_updates_observed(txn, slot, Some(&mut **observe))?,
        None => store.port_document_updates(txn, slot)?,
    };
    for update in updates {
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

pub(super) fn resolve_record_body(
    store: &impl crate::store::ManifestDbs,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    body: &[u8],
    mut observe: Option<&mut DocumentReadObserver<'_>>,
) -> Result<Vec<u8>> {
    let h = match observe.as_mut() {
        Some(observe) => {
            let bytes = ENTITY_DOC_HEAD.get_borrowed(store, txn, &HexId(*entity))?;
            let key = ENTITY_DOC_HEAD.key_bytes(&HexId(*entity));
            observe(DocumentRead::Row {
                table: ENTITY_DOC_HEAD.decl(),
                key: &key,
                value: bytes.as_deref(),
            });
            bytes
                .map(|bytes| ENTITY_DOC_HEAD.decode_value(&bytes))
                .transpose()?
        }
        None => ENTITY_DOC_HEAD.get(store, txn, &HexId(*entity))?,
    };
    let Some(h) = h else {
        return Ok(body.to_vec());
    };
    require_live(store, txn, entity)?;
    let doc = load(store, txn, &h, observe)?;
    body_with_document(&h.field, body, &doc)
}

/// The original pointer-field head read, before native decode and entity binding.
pub(super) fn pointer_field_in(
    dbs: &impl crate::side_table::SideTableDbs,
    txn: &RoTxn<'_>,
    entity: &EntityId,
    observe: Option<&mut DocumentReadObserver<'_>>,
) -> Result<Option<super::TextField>> {
    let head = match observe {
        Some(observe) => {
            let raw = ENTITY_DOC_HEAD.get_borrowed(dbs, txn, &HexId(*entity))?;
            observe(DocumentRead::Row {
                table: ENTITY_DOC_HEAD.decl(),
                key: &ENTITY_DOC_HEAD.key_bytes(&HexId(*entity)),
                value: raw.as_deref(),
            });
            raw.map(|raw| ENTITY_DOC_HEAD.decode_value(&raw))
                .transpose()?
        }
        None => ENTITY_DOC_HEAD.get(dbs, txn, &HexId(*entity))?,
    };
    Ok(head
        .filter(|head| head.entity == entity.to_hex())
        .map(|head| head.field))
}
