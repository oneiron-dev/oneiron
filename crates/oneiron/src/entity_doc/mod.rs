//! Durable, bounded entity text documents, anchored edits, fork sets and owner purge.
//!
//! The ledger row keeps its immutable core and a document pointer. Text writes
//! commit CRDT operations; only indexed projections may materialize the text.
//! Documents are loaded lazily, snapshot before ordered pending updates.

#[cfg(feature = "sync")]
mod carried;
pub(crate) mod checkpoint;
mod citation_floor;
mod commit_receipts;
mod doc_actor;
mod document;
mod forks;
mod history_erase;
mod lift;
mod message_stream;
mod metadata;
pub mod office;
mod pins;
mod promotion_evidence;
mod proposal_lineage;
mod prose_admission;
mod quote_citation;
pub(crate) use promotion_evidence::{
    promotion_evidence_source_in_txn, retain_fresh_claim_citations_in_txn,
    verify_promotion_evidence_in_txn,
};
mod recovery;
mod registry;
mod summary;
pub(crate) use summary::{
    birth_summary_in_txn, open_summary_proposal, summary_frontier_in_txn, summary_meta_in_txn,
    summary_read_in_txn, summary_text_in_txn,
};
pub mod review_explainer;
mod side_keys;
mod storage;
#[cfg(feature = "sync")]
mod sweep;
#[cfg(feature = "sync")]
mod sync;
pub(crate) use citation_floor::record_citation_floor_in_txn;
pub(crate) use commit_receipts::commit_input_rows_in_txn;
pub(crate) use message_stream::{
    append_message_stream_in_txn, authorize_message_continuation_in_txn,
    ensure_quote_document_in_txn, quote_birth_admits_in,
};
pub(crate) use pins::pin_body_quote_at_birth_in_txn;
pub(crate) use recovery::{
    capture as capture_canonical, restore as restore_canonical,
    restore_proposals as restore_canonical_proposals,
};
mod verbs;

#[cfg(feature = "sync")]
pub(crate) use carried::{CarriedDocument, DocumentMerge, moved_pointer_row_in_txn};
pub use doc_actor::DocActor;
pub use document::{Birth, EntityDoc, TextChange};
pub use forks::{
    ACTOR_ERASE_PENDING_ENTITY_DOC_FORK, DocAuthorization, ForkRecord, ForkRequest, ForkStatus,
    PendingDocForkErase, ProposalBundle, SettleVerb, TextReceipt,
};
pub(crate) use forks::{
    erase_fork_actor_in_txn, erase_proposal_actor_in_txn, erase_receipt_actor_in_txn,
};
pub use history_erase::TextHistoryErase;
pub(crate) use history_erase::admit_history_erase_in_txn;
pub(crate) use lift::lift_entity_text_in_txn;
pub use metadata::MetadataEdit;
pub use office::{DeckBody, DeckExport, DeckReview, ReevalWake};
#[cfg(feature = "sync")]
pub(crate) use pins::PinMerge;
pub use pins::{CitationPin, CursorResolution, PurgeReceipt};
pub(crate) use pins::{erase_pin_actor_in_txn, erase_purge_actor_in_txn};
pub(crate) use registry::EntityDocRegistry;
pub use registry::{EntityDocumentHead, EntityDocumentView, RegistryStatus};
pub use storage::TextField;
pub(crate) use storage::{
    document_text_fields, erase_in_txn, guard_record_put, has_record_head, pointer_field_in,
    record_bodies_at_in_txn, record_body_at, record_body_history_in_txn, record_document,
    record_head_bytes, reindex_repo_document_in_txn, resolve_record_body,
};
#[cfg(feature = "sync")]
pub(crate) use sweep::{compact_entity_doc_for_sweep, entity_doc_slots_in};
#[cfg(feature = "sync")]
pub(crate) use sync::{
    SyncEdit, edit_sync_text_in_txn, join_sync_update_in_txn, replace_sync_text_in_txn,
    sync_text_in,
};
pub use verbs::{AnchoredEdit, EditVerb, TextAnchor, TextUpdateOutcome, TextUpdateRequest};

/// Resolve an active document's identity and live frontier in a caller-owned
/// transaction. An unmigrated row has no document plane.
pub(crate) fn source_frontier_in_txn(
    store: &crate::store::Store,
    txn: &heed::RoTxn<'_>,
    entity: &crate::EntityId,
) -> crate::Result<Option<Vec<u8>>> {
    if !storage::has_record_head(store, txn, entity)? {
        return Ok(None);
    }
    let head = storage::head(store, txn, entity)?;
    let doc = storage::load(store, txn, &head)?;
    let mut pin = head.incarnation.into_bytes();
    pin.extend_from_slice(&doc.frontier());
    Ok(Some(pin))
}

use crate::error::{ArtifactError, Error};

fn invalid(reason: &'static str) -> Error {
    Error::Artifact(ArtifactError::InvalidEditManifest(reason))
}

/// Fault injection for recovery checks: drops `entity`'s document head row
/// alone, as a damaged vault can lose it, keeping the stored history. The
/// returned closure puts the row back.
#[cfg(all(test, feature = "sync"))]
pub(crate) fn lose_head_for_test(
    vault: &crate::Vault,
    entity: &crate::EntityId,
) -> crate::Result<impl FnOnce(&crate::Vault) -> crate::Result<()>> {
    let entity = *entity;
    let mut txn = vault.store.env.write_txn()?;
    let key = crate::side_table::HexId(entity);
    let head = storage::ENTITY_DOC_HEAD
        .get(&vault.store, &txn, &key)?
        .ok_or(Error::EntityNotFound)?;
    storage::ENTITY_DOC_HEAD.delete(&vault.store, &mut txn, &key)?;
    txn.commit()?;
    Ok(move |vault: &crate::Vault| {
        let mut txn = vault.store.env.write_txn()?;
        let key = crate::side_table::HexId(entity);
        storage::ENTITY_DOC_HEAD.put(&vault.store, &mut txn, &key, &head)?;
        txn.commit()?;
        Ok(())
    })
}

#[cfg(test)]
mod tests;
