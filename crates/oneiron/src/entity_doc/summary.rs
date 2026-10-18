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
            self.authorize_shared_content_write_in_txn(txn, *summary, &actor)?;
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

/// One coherent SUMMARY editor projection inside the reader's admitted snapshot.
pub(crate) fn summary_read_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    entity: &EntityId,
    spans: &[crate::scope_summary::SummarySpan],
) -> Result<crate::scope_summary::SummaryReadView> {
    let (head, doc) = summary_doc(vault, txn, entity)?;
    let row = vault.store.port_entity_record(txn, entity)?.ok_or(Error::EntityNotFound)?;
    let logical = super::resolve_record_body(&vault.store, txn, entity, &row.body)?;
    let body = crate::scope_summary::decode_scope_summary_body(&logical)?;
    let anchors = spans.iter()
        .map(|span| super::verbs::make_anchor(&doc, *entity, span.start, span.end))
        .collect::<Result<Vec<_>>>()?;
    Ok(crate::scope_summary::SummaryReadView {
        summary_ref: entity.to_hex(),
        document: head.document,
        frontier: doc.frontier(),
        text: doc.text(),
        metadata: summary_meta_in_txn(vault, txn, entity)?,
        covers: body.covers.iter().map(EntityId::to_hex).collect(),
        read_refs: crate::ports::dependency_sources_in(&vault.store, txn, entity)?
            .iter().map(EntityId::to_hex).collect(),
        anchors,
        birth: doc.birth().clone(),
    })
}

/// Opens one SUMMARY change through the common fork engine. Its keep fence,
/// source admission, provenance and erasure dependencies co-commit with it.
pub(crate) fn open_summary_proposal(
    memory: &crate::memory::Memory<'_>,
    request: &super::ForkRequest,
    keep: Option<&str>,
    read_refs: &[String],
    authorization: &DocAuthorization<'_>,
) -> crate::memory::MemoryResult<super::ProposalBundle> {
    use super::forks::{ENTITY_DOC_FORK, ENTITY_DOC_PROPOSAL_BUNDLE, ENTITY_DOC_RECEIPT};
    use super::side_keys::HexPair;
    use crate::side_table::HexId;

    let vault = memory.vault();
    let reader = memory.read_lane(crate::claim::ClaimReadStatus::Recorded)?;
    let sources = read_refs.iter()
        .map(|reference| crate::memory::resolve_entity_ref(vault, reference))
        .collect::<crate::memory::MemoryResult<Vec<_>>>()?;
    if sources.contains(&request.entity) {
        return Err(crate::memory::MemoryError::bad_request("a SUMMARY cannot be its own generation source"));
    }
    let proposal = vault.new_entity_id()?;
    let mut registry = vault.entity_docs.lock()
        .map_err(|_| super::invalid("document registry poisoned"))?;
    let bundle = vault.try_with_write_txn_grouped(|txn| {
        vault.authorize_shared_content_write_in_txn(txn, request.entity, &request.actor)?;
        let mut admitted = sources.clone();
        admitted.push(request.entity);
        if reader.get_entities_parts_in_txn(txn, &admitted)?.iter().any(Option::is_none) {
            return Err(crate::memory::MemoryError::new(
                crate::memory::MEMORY_CODE_NOT_FOUND,
                "SUMMARY generation input is absent or not readable",
                &[],
            ));
        }
        let (_, live) = summary_doc(vault, txn, &request.entity)?;
        if let Some(keep) = keep {
            let base = live.fork(&request.base)?;
            let base_keep = base.metadata()?.get("keep")
                .and_then(rmpv::Value::as_str).map(str::to_owned);
            if summary_meta_in_txn(vault, txn, &request.entity)?.keep != keep
                || base_keep.as_deref() != Some(keep)
            {
                return Err(Error::ConcurrentWrite("summary keep memo changed").into());
            }
        }
        let mut bundle = super::forks::open_proposal_in_txn(
            vault, txn, &proposal, std::slice::from_ref(request), authorization,
            vault.now_recorded_at(),
        )?;
        let refs: Vec<String> = sources.iter().map(EntityId::to_hex).collect();
        for record in &mut bundle.forks {
            record.read_refs.clone_from(&refs);
            record.keep = keep.map(str::to_owned);
            ENTITY_DOC_FORK.put(&vault.store, txn, &record.fork, record)?;
        }
        ENTITY_DOC_PROPOSAL_BUNDLE.put(&vault.store, txn, &proposal.to_hex(), &bundle)?;
        for mut receipt in super::forks::receipts(&vault.store, txn, &request.entity)? {
            if receipt.proposal == proposal.to_hex() {
                receipt.read_refs.clone_from(&refs);
                let key = HexPair(HexId(request.entity), HexId(EntityId::from_hex(&receipt.receipt)?));
                ENTITY_DOC_RECEIPT.put(&vault.store, txn, &key, &receipt)?;
            }
        }
        // Pending output is still retained text. Its sources must reach the
        // entity's complete fork set when one of them is erased.
        for source in &sources {
            crate::ports::record_derived_edge_in_txn(&vault.store, txn, &request.entity, source)?;
        }
        Ok::<_, crate::memory::MemoryError>(bundle)
    })?;
    registry.clear();
    memory.produced_from(sources);
    Ok(bundle)
}
