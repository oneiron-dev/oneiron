//! Attributed NOTE records with built-in, plugin and registered PACK kinds.
//! Editable text and citation authority use the canonical entity-document path.

use crate::entity_id::EntityId;
use crate::error::Result;

pub use crate::store::note_body::{
    NOTE_BODY_KEYS, NoteBody, NoteKind, NoteScope, NoteWriteEnvelope, TakeTarget, decode_note_body,
    encode_note_body,
};
pub(crate) use crate::store::note_body::{decode_note_body_using, validate_markdown};

mod reads;
pub(crate) use reads::PreparedNoteRead;
pub use reads::{
    NoteAccessRequest, NoteAnchoredSpan, NoteEditorBinding, NoteEditorCloseRequest,
    NoteEditorClosed, NoteHistoryView, NoteIndexedReadRequest, NoteReadRequest, NoteReadSource,
    NoteReadSpan, NoteReadView,
};
mod archive_import;
#[cfg(feature = "sync")]
mod residence_read;
pub use archive_import::ImportedNoteRead;
pub(crate) use archive_import::{ArchivedNoteAdmission, archived_note_body};
#[cfg(feature = "sync")]
pub(crate) use residence_read::opened_note_view;
mod archive_read;
pub(crate) mod documents;
pub(crate) mod erase;
mod kinds;
mod lifecycle;
pub(crate) mod recovery;
pub(crate) mod revision;
pub(crate) mod storage;
pub(crate) use kinds::validate_registered_kind;
mod proposal_doors;
pub use proposal_doors::{
    NoteForkReadRequest, NoteForkRecordView, NoteForkRequest, NoteForkView, NoteLandingView,
    NoteProposalForkRef, NoteProposalOpenRequest, NoteProposalRequest, NoteProposalView,
    NoteVersionTree,
};
mod carrier_erase;
mod proposals;
mod run_review;
pub(crate) use run_review::{
    RunNoteUndo, revert_run_note_in_txn, run_note_review_in_txn, settle_run_note_in_txn,
};
mod tombstone_review;
mod verbs;
mod write_gate;
pub use documents::{
    NoteAnchor, NoteDocument as NoteProgramDocument, NoteProgramEdit, NoteProgramEditOutcome,
    NoteVersion,
};
pub(crate) use kinds::{COMPACTION_INTENT_NOTE_KIND, LENS_INTENT_NOTE_KIND, descriptor_in_txn};
pub use kinds::{
    ContextDefault, DISSENT_NOTE_KIND, ExtractionDefault, NoteKindDescriptor, RetentionDefault,
};
pub use lifecycle::{NoteLifecycleStatus, NoteLifecycleView, NoteRefRequest, NoteSeal};
mod overrides;
#[cfg(feature = "sync")]
pub(crate) use lifecycle::note_seal_in_txn;
pub(crate) use lifecycle::{erase_seal_actor_in_txn, note_sealed_in_txn, seal_note_in_txn};
#[cfg(feature = "sync")]
pub(crate) use overrides::encode_frame_overrides_in_txn;
pub(crate) use overrides::note_defaults_in_txn;
pub use overrides::{NoteDefaultsView, NoteOverrides, SetNoteOverridesRequest};
pub use proposals::{
    ACTOR_ERASE_PENDING_NOTE_FORK, NoteActor, NoteFork, NoteLandingReceipt, NoteReviewBundle,
    NoteVerdict, PendingNoteForkErase,
};
pub(crate) use proposals::{
    erase_fork_actor_in_txn, erase_proposal_actor_in_txn, erase_receipt_actor_in_txn,
    recovery_fork_value,
};
pub use sync_rows::{ACTOR_ERASE_NOTE_REQUEST_RECEIPT, NoteRequestReceiptErase};
pub use tombstone_review::NoteTombstoneProposal;
pub(crate) use tombstone_review::{
    decline_tombstone, open_tombstone_proposals_in_txn, review_note_tombstones, tombstone_accepted,
    tombstone_still_proposed_in_txn,
};
pub(crate) use write_gate::check_doc_plane_note_commit_in_txn;
/// Registry-aware decoding for stored NOTE cores, including PACK-defined kinds.
pub(crate) fn decode_note_body_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    bytes: &[u8],
) -> Result<NoteBody> {
    let body = decode_note_body_using(bytes, NoteKind::wire)?;
    kinds::context_in_txn(store, txn, body.kind.as_str().as_ref())?;
    Ok(body)
}

/// Shared NOTE admission. Ordinary retrieval excludes every owner-only and
/// explicit-only NOTE, by the context its kind gives it or it overrides.
pub(crate) fn note_body_readable(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    bytes: &[u8],
    actor: Option<&EntityId>,
) -> Result<bool> {
    let Ok(body) = decode_note_body_using(bytes, NoteKind::wire) else {
        return Ok(false);
    };
    let context = overrides::note_context_in_txn(store, txn, id, body.kind.as_str().as_ref())?;
    Ok(match context {
        ContextDefault::OwnerOnly | ContextDefault::ExplicitOnly => match actor {
            Some(actor) => {
                body.author_ref.is(*actor) || reader_imported_note(store, txn, &body, *actor)?
            }
            None => false,
        },
        ContextDefault::RelationshipScoped | ContextDefault::VaultReadable => true,
    })
}

/// Whether a NOTE reads to every reader the vault's other gates admit: its
/// kind's context, or its override, is vault-readable. An owner-only,
/// explicit-only or relationship-scoped NOTE carries a read restriction of
/// its own (its author, importer, consent or relationship scope), which a
/// record that only copies its scope position cannot hold (FIX 2783).
pub(crate) fn note_vault_readable_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    bytes: &[u8],
) -> Result<bool> {
    // A migrated NOTE keeps its markdown on its document plane: judge the
    // logical body, as a scoped NOTE read does.
    let resolved = crate::entity_doc::resolve_record_body(store, txn, id, bytes)?;
    let Ok(body) = decode_note_body_using(&resolved, NoteKind::wire) else {
        return Ok(false);
    };
    let context = overrides::note_context_in_txn(store, txn, id, body.kind.as_str().as_ref())?;
    Ok(matches!(context, ContextDefault::VaultReadable))
}

/// Whether `body` came in through an import for `reader`: its author is a
/// folder's import MACHINE that imports for that reader. Such a note reads
/// as its importer's own, though the importer did not write it (OF-554). An
/// erased author is no importer's.
pub(crate) fn reader_imported_note(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    body: &NoteBody,
    reader: EntityId,
) -> Result<bool> {
    let Some(author) = body.author_ref.id() else {
        return Ok(false);
    };
    Ok(import::note_importer_in_txn(store, txn, &author)? == Some(reader))
}

/// Whether NOTE `id` is explicit-only, by its kind or its override: out of
/// default context, and readable on an explicit read by every reader its
/// policy admits.
pub(crate) fn note_explicit_only_in_txn(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &NoteBody,
) -> Result<bool> {
    Ok(
        overrides::note_context_in_txn(store, txn, id, body.kind.as_str().as_ref())?
            == ContextDefault::ExplicitOnly,
    )
}

/// A refused private row must not disclose its existence through a receipt.
/// All NOTE kinds are omitted from denial counts: without admission, a reader
/// cannot safely distinguish a public NOTE from an owner-only one. Diary-pair
/// grants and malformed grant bodies are likewise opaque to ordinary readers.
pub(crate) fn countable_read_suppression(entity_type: u8, body: &[u8]) -> bool {
    match entity_type {
        crate::registry::ENTITY_TYPE_NOTE => false,
        crate::registry::ENTITY_TYPE_ACCESS_GRANT => {
            crate::access_grant::decode_access_grant_body(body).is_ok_and(|grant| {
                !matches!(
                    grant.scope,
                    crate::access_grant::AccessGrantScope::DiaryCoreference { .. }
                )
            })
        }
        _ => true,
    }
}

/// Ordinary retrieval's NOTE privacy floor. Unrelated entity kinds and missing
/// graph endpoints retain their existing admission semantics.
pub(crate) fn ordinary_entity_visible(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<bool> {
    let Some(raw) = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)? else {
        return Ok(true);
    };
    let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw) else {
        return Ok(false);
    };
    Ok(header.entity_type != crate::registry::ENTITY_TYPE_NOTE
        || note_body_readable(
            store,
            txn,
            id,
            &raw[crate::batch::ENTITY_METADATA_HEADER_LEN..],
            None,
        )?)
}

/// [`ordinary_entity_visible`] judged on a record the caller already
/// decoded under this same transaction: its type byte and body stand in
/// for the raw fetch and header parse.
pub(crate) fn ordinary_entity_visible_with_body(
    store: &impl crate::store::ManifestDbs,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    entity_type: u8,
    body: &[u8],
) -> Result<bool> {
    Ok(entity_type != crate::registry::ENTITY_TYPE_NOTE
        || note_body_readable(store, txn, id, body, None)?)
}

#[cfg(test)]
mod tests;

pub(crate) mod checkpoint;
mod citation_erase;
mod delete;
#[cfg(feature = "sync")]
mod local_discard;
mod pin_index;
mod side_keys;
mod sync_rows;
pub(crate) use citation_erase::{
    any_citation_erase_pending, ensure_citations_ready, erase_citations_in_txn,
    erase_restored_citations_in_txn,
};
pub(crate) use pin_index::citation_delete_scope_exists;
#[cfg(feature = "sync")]
pub(crate) use pin_index::{remove_citation_request, track_citation_request};
#[cfg(feature = "sync")]
mod citation_residence;
#[cfg(feature = "sync")]
pub(crate) use citation_residence::{
    erase_residence_copies_of_in_txn, refuse_erased_residence_copy_in_txn,
};
#[cfg(feature = "sync")]
mod citation_scrub;
mod free_text;
#[cfg(feature = "sync")]
mod pending_request;
#[cfg(feature = "sync")]
pub(crate) use citation_erase::validate_pins as validate_citation_dependencies;
#[cfg(feature = "sync")]
pub(crate) use citation_scrub::scrub_pending_citations;
#[cfg(feature = "sync")]
pub(crate) use pending_request::{PendingNoteRequest, admit_note_operation_in_txn};
#[cfg(feature = "sync")]
mod fork_downlink;
#[cfg(feature = "sync")]
pub(crate) use fork_downlink::{
    authority_fork_frames_in_txn, fork_state_cites_withheld, install_authority_fork,
    settle_authority_forks,
};
#[cfg(feature = "sync")]
mod fork_upload;
#[cfg(feature = "sync")]
pub use fork_upload::{NoteForkUpload, NoteForkUploadOutcome, NoteForkUploadReceipt};
#[cfg(feature = "sync")]
pub(crate) use fork_upload::{fork_upload_frame_in_txn, uploadable_fork_in_txn};
#[cfg(test)]
mod erasure_tests;
mod live_body;
pub(crate) use live_body::{live_body_from_in_txn, live_body_in_txn};
mod brief_doors;
pub use brief_doors::{AuthorBriefRequest, BriefClaimCitation, BriefKindStamp};
mod kind_contract;
#[cfg(all(test, feature = "sync"))]
mod live_body_tests;
pub(crate) use delete::delete_document_in_txn;
#[cfg(feature = "sync")]
pub(crate) use local_discard::{discard_bundle_explainers_in_txn, discard_workflow_in_txn};
mod id_codec;
pub use kind_contract::{
    BriefKindContract, NoteContextDefault, NoteExtractionDefault, NoteRetentionDefault,
};
mod birth;
mod coreference;
pub(crate) use coreference::{edge_access_in as diary_edge_access_in, readable_through_link};
#[cfg(feature = "sync")]
mod brief_view;
mod document;
pub(crate) fn live_frontier_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Vec<u8>> {
    Ok(document_store::load(vault, txn, id)?.view()?.frontier)
}

/// The historical lift sweep's door to a NOTE (OF-067; FIX 2967): the keys
/// of each text it keeps are marked under that text's hash, as a carrier's
/// are, each going to custody with the NOTE named as where it was found.
/// `kept` is what the sweep's census read of it (its stored body, the text
/// it was indexed with or staged); the door adds its live text, its title
/// and each pin's quote. The document, its history and seal, each pin's
/// quote, hash and cursors and the title's reservation stay as they are, and
/// a reader other than the owner reads each key as its handle. The outcome
/// is the texts' as one: a hit left unplaced first, then a key marked now,
/// then one marked before.
pub(crate) fn lift_note_in_txn(
    vault: &crate::Vault,
    txn: &mut heed::RwTxn<'_>,
    id: EntityId,
    kept: &[Vec<u8>],
) -> Result<crate::batch::secret_scan::CarrierText> {
    use crate::batch::secret_scan::{CarrierText, mark_carrier_text_in_txn};
    let view = document_store::load(vault, txn, id)?.view()?;
    let mut texts = Vec::<(&str, &[u8])>::new();
    for text in kept {
        texts.push(("note:kept", text.as_slice()));
    }
    texts.push(("note:markdown", view.markdown.as_bytes()));
    if let Some(title) = &view.title {
        texts.push(("note:title", title.as_bytes()));
    }
    for pin in &view.pins {
        texts.push(("note:quote", pin.quote_text.as_bytes()));
    }
    let mut outcome = CarrierText::Clean;
    for (place, text) in texts {
        outcome = match (
            outcome,
            mark_carrier_text_in_txn(vault, txn, id, place, text)?,
        ) {
            (CarrierText::Unplaceable(reason), _) | (_, CarrierText::Unplaceable(reason)) => {
                CarrierText::Unplaceable(reason)
            }
            (CarrierText::Minted(reason), _) | (_, CarrierText::Minted(reason)) => {
                CarrierText::Minted(reason)
            }
            (CarrierText::Marked, _) | (_, CarrierText::Marked) => CarrierText::Marked,
            (CarrierText::Clean, CarrierText::Clean) => CarrierText::Clean,
        };
    }
    Ok(outcome)
}

/// A NOTE's title and each pin's quote: the text it keeps beside its body,
/// which the historical lift sweep's census reads (OF-067).
pub(crate) fn note_side_text_in_txn(
    vault: &crate::Vault,
    txn: &heed::RoTxn<'_>,
    id: EntityId,
) -> Result<Vec<String>> {
    let doc = document_store::load(vault, txn, id)?;
    let mut text: Vec<String> = doc.title()?.into_iter().collect();
    text.extend(doc.pins()?.into_iter().map(|pin| pin.quote_text));
    Ok(text)
}

mod document_store;
mod saved;
pub(crate) use document_store::deck_outline_document_in_txn;
pub(crate) use document_store::resolve_deck_pin_in_txn;
pub(crate) use document_store::{
    DeckSpanObservation, DeckSpanReads, deck_outline_markdown_at_in_txn, observe_deck_span_in_txn,
};
pub(crate) use saved::PreparedSavedNote;
mod files;
pub use files::{
    DEFAULT_FILES_EXCLUDE, FILES_DEFAULT_KIND, FILES_TEXT_EXTENSIONS, FILES_WORLD_NAME, FileFacts,
    FileHandle, FileMeta, FileReadiness, FilesPlacement, FilesWorld, NameOnlyFile, NameOnlyReason,
};
mod folder_source;
pub(crate) use folder_source::erase_folder_source_actor_in_txn;
pub use folder_source::{
    FileOriginal, FolderFile, FolderFileState, FolderRescan, FolderRescanReport, FolderSource,
    FolderSourceFile, OriginalBytes,
};
mod import;
pub use import::{
    ImportedFile, ImportedNote, ImportedNoteBatch, ImportedNoteBatchReceipt, ImportedNoteLink,
    ImportedNoteStanding, NOTES_IMPORT_SOURCE,
};
pub(crate) use import::{folder_import_creator_in_txn, imported_note_source_in_txn};
mod title_index;
pub(crate) use birth::{document_birth_in_txn, room_birth_document_in_txn};
// FIX 4280: a room's NOTE read where the room holds it, and the sizes a
// store-aware entrance measures of a NOTE document (rule 5).
mod room_reads;
mod scan;
pub(crate) use scan::measure as measure_note_document;
#[cfg(feature = "sync")]
pub(crate) use title_index::replace_recovered_set_in_txn as replace_recovered_titles_in_txn;
mod operations;
pub use operations::{NoteAuthorship, NoteChange, NoteOperation, NoteOperationReceipt};
#[cfg(feature = "sync")]
pub(crate) mod frame_envelope;
#[cfg(feature = "sync")]
mod replica;
mod token_uses;
#[cfg(feature = "sync")]
pub use brief_view::{BriefCitationView, BriefView};
#[cfg(feature = "sync")]
pub(crate) use replica::{
    import_note_from_authority, text_withheld_by_worlds, validate_note_export,
};
#[cfg(all(test, feature = "sync"))]
mod document_tests;
#[cfg(all(test, feature = "sync"))]
mod sync_tests;
pub(crate) use document::MAX_NOTE_BYTES;
pub use document::{
    NoteDocumentView, NotePin, NoteScalarEdit, NoteScalarEditOutcome, NoteSpanResolution,
};
pub use document::{NoteScalarEdit as NoteEdit, NoteScalarEditOutcome as NoteEditOutcome};

#[cfg(test)]
mod program_tests;
#[cfg(test)]
mod shared_membership_tests;

#[cfg(test)]
mod adapter_tests;
