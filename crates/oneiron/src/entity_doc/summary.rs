//! Scope-summary documents: retained derivations, purpose and editor `keep` memo.

use super::{DocAuthorization, EntityDoc, TextField, storage};
use crate::error::{Error, Result};
use crate::ports::{EntityStoreMaintenance, EntityStoreRead, TombstoneStoreRead};
use crate::scope_summary::ScopeSummaryMetadata;
use crate::sync::loro_support::{map_get_bytes, map_insert_bytes};
use crate::{EntityId, Vault, WriteActor};

fn summary_doc(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<(storage::Head, EntityDoc)> {
    let state = vault.store.port_deletion_state(txn, entity)?;
    if state.deleted
        || vault
            .store
            .port_entity_record(txn, entity)?
            .is_none_or(|row| row.entity_type != crate::registry::ENTITY_TYPE_SUMMARY)
    {
        return Err(Error::EntityNotFound);
    }
    let head = storage::ENTITY_DOC_HEAD
        .get(&vault.store, txn, &crate::side_table::HexId(*entity))?
        .ok_or(Error::EntityNotFound)?;
    let doc = storage::load(&vault.store, txn, &head)?;
    Ok((head, doc))
}

pub(crate) fn summary_meta_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<ScopeSummaryMetadata> {
    let (_, doc) = summary_doc(vault, txn, entity)?;
    let meta = doc.doc.get_map("meta");
    Ok(ScopeSummaryMetadata {
        purpose: storage::decode(
            &map_get_bytes(&meta, "purpose")
                .ok_or(Error::CorruptedIndex("summary purpose metadata"))?,
        )?,
        keep: doc
            .metadata()?
            .get("keep")
            .and_then(rmpv::Value::as_str)
            .ok_or(Error::CorruptedIndex("summary keep metadata"))?
            .to_owned(),
        derivation: storage::decode(
            &map_get_bytes(&meta, "derivation")
                .ok_or(Error::CorruptedIndex("summary derivation metadata"))?,
        )?,
    })
}

pub(crate) fn summary_frontier_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<Vec<u8>> {
    let (head, doc) = summary_doc(vault, txn, entity)?;
    let mut frontier = head.incarnation.into_bytes();
    frontier.extend_from_slice(&doc.frontier());
    Ok(frontier)
}

pub(crate) fn summary_text_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
) -> Result<String> {
    Ok(summary_doc(vault, txn, entity)?.1.text())
}

pub(crate) fn birth_summary_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    entity: EntityId,
    actor: WriteActor,
    at: u64,
    metadata: &ScopeSummaryMetadata,
) -> Result<()> {
    let row = vault
        .store
        .port_entity_record(txn, &entity)?
        .ok_or(Error::EntityNotFound)?;
    let field = TextField::MapField("text".to_owned());
    let (text, record_metadata, pointer) =
        storage::replace_text(&row.body, &field, &entity.to_hex())?;
    let keep_value = rmpv::Value::from(metadata.keep.as_str());
    super::metadata::validate_metadata("keep", &keep_value)?;
    let keep = super::metadata::encode_value(&keep_value)?;
    let purpose = rmp_serde::to_vec_named(&metadata.purpose)
        .map_err(|_| super::invalid("summary purpose encoding"))?;
    let derivation = rmp_serde::to_vec_named(&metadata.derivation)
        .map_err(|_| super::invalid("summary derivation encoding"))?;
    let doc = EntityDoc::open_initialized(
        loro::LoroDoc::new(),
        entity,
        &text,
        actor,
        at,
        |doc| {
            EntityDoc::replace_metadata(doc, &record_metadata)?;
            EntityDoc::set_record_fields(
                doc,
                &record_metadata.keys().cloned().collect::<Vec<_>>(),
            )?;
            let meta = doc.get_map("meta");
            map_insert_bytes(&meta, "purpose", &purpose)?;
            map_insert_bytes(&meta, "keep", &keep)?;
            map_insert_bytes(&meta, "derivation", &derivation)
        },
        None,
    )?;
    super::forks::bind_actor(vault, txn, &doc, actor, at)?;
    crate::federation::record_scope::restamp_document_pointer(
        &vault.store,
        txn,
        entity,
        row.entity_type,
        &row.body,
        &pointer,
    )?;
    vault
        .store
        .port_entity_document_pointer_put(txn, &entity, &pointer)?;
    let mut head = storage::Head {
        entity: entity.to_hex(),
        incarnation: EntityId::now().to_hex(),
        document: entity.to_hex(),
        field,
        generation: 0,
        pending: 0,
    };
    storage::persist(vault, txn, &entity, &mut head, &doc, None)
}

impl Vault {
    /// Opens the derivation and document memo without treating an old
    /// artifact's edited prose as new evidence.
    pub fn scope_summary_metadata(&self, summary: &EntityId) -> Result<ScopeSummaryMetadata> {
        let txn = self.store.env.read_txn()?;
        summary_meta_in_txn(self, &txn, summary)
    }

    /// Commits a distilled editor memo at exactly the frontier its producer
    /// read. A concurrent edit refuses rather than silently losing a want.
    pub fn set_scope_summary_keep(
        &self,
        summary: &EntityId,
        frontier: &[u8],
        keep: &str,
        actor: WriteActor,
        authorization: &DocAuthorization<'_>,
        at: u64,
    ) -> Result<()> {
        self.with_write_txn_grouped(|txn| {
            super::forks::authorize(self, txn, authorization, summary, actor)?;
            let (mut head, doc) = summary_doc(self, txn, summary)?;
            if doc.frontier() != frontier {
                return Err(Error::ConcurrentWrite(
                    "summary editor memo frontier changed",
                ));
            }
            let keep_value = rmpv::Value::from(keep);
            super::metadata::validate_metadata("keep", &keep_value)?;
            let keep = super::metadata::encode_value(&keep_value)?;
            let before = doc.doc.oplog_vv();
            super::forks::bind_actor(self, txn, &doc, actor, at)?;
            map_insert_bytes(&doc.doc.get_map("meta"), "keep", &keep)?;
            super::document::stamp(&doc.doc, actor, at, "summary_keep")?;
            storage::persist(self, txn, summary, &mut head, &doc, Some(&before))
        })
    }
}
