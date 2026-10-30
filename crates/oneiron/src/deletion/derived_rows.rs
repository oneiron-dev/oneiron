//! Rows a record feeds outside the generic index set, torn with the record.
//!
//! Both delete doors call [`tear_derived_rows_in_txn`]: the physical
//! `deindex_entity` (batch delete, hard purge, replayed hard tombstone) and the
//! soft erase that leaves a shell. Each row family here was added after those
//! doors, so neither reached it (F08).
//!
//! A module whose side tables key rows by an entity whose erase it does not
//! run (a typed body, an artifact's office body or deck) registers one eraser
//! in [`ERASERS`], one line each.
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// Removes the rows one module keys by the erased entity, and is a no-op for
/// an entity it holds nothing for. Runs in the erase transaction, at both
/// delete doors, before the record's body and edges go.
pub(crate) type EntitySideRowEraser = fn(&Store, &mut heed::RwTxn<'_>, &EntityId) -> Result<()>;

/// Every per-entity eraser, one line per module.
const ERASERS: &[EntitySideRowEraser] = &[
    crate::typed_body::erase_in_txn,
    crate::office_body::erase_in_txn,
    crate::edit_roundtrip::deck_create::erase_in_txn,
    crate::memory::erase_stream_seeds_in_txn,
    crate::conversation::erase_chat_breakpoints_in_txn,
    crate::store::legal_hold::erase_in_txn,
    crate::workspace_roster::erase_room_side_rows,
    crate::task_verb::erase_report_journal_in_txn,
    crate::task_verb::erase_lifecycle_receipts_in_txn,
    crate::vault_cleanup::erase_in_txn,
    crate::dreamer_runner::maintenance::erase_source_copies_in_txn,
    // FIX 9929: a public model step's kept request and result.
    crate::llm::erase_submissions_in_txn,
    // FIX 10089: every verdict memo the erased row is a source of.
    crate::saved_query::erase_memos_for_source_in_txn,
    // FIX 10466: every inference snapshot whose dependency set reaches it.
    crate::inference_snapshot::erase_in_txn,
    // FIX 10260: a MESSAGE's kept reply assertions.
    crate::memory::erase_reply_assertions_in_txn,
    // FIX 9970: a TURN's unpersisted-wake label.
    crate::memory::erase_turn_wake_label_in_txn,
    // FIX 7608 S3F: a derived text's index copy, and the copies derived from it.
    crate::embed::retire_repo_derived_index_copies_in_txn,
    // FIX 9752: a fitted section install's receipt, with the skill or the
    // install claim it names.
    crate::context_board::erase_section_fit_receipts_in_txn,
    // FIX 9949: an uploaded or generated ASSET's reference to its bytes.
    crate::memory::release_asset_blob_in_txn,
    // FIX 10219: a subject's recognition prints, samples and active pointer.
    crate::voice_identity::erase_recognition_for_subject_in_txn,
    // FIX 9805: a reviewed claim's teaching copies in the miner.
    crate::edit_distance::miner::erase_source_claim_in_txn,
    // FIX 9918: a typed question's copies of an erased judgment answer.
    crate::llm::decision::questions::erase_question_source_in_txn,
    // FIX 10019: an erased export's accepted persona copy.
    crate::persona_snapshot::erase_in_txn,
    // FIX 9598: an erased claim's owed VAD consolidation.
    crate::store::settle_claim_vad_in_txn,
    // FIX 9636: an erased booking EVENT's receipt intake and invite addresses.
    crate::booking::lifecycle::erase_booking_receipt_carriers_in_txn,
    // FIX 9876: an imported MESSAGE's text hash in the history import ledger.
    crate::ingest::history::erase_message_in_txn,
    // FIX 9775: a PERSON's trusted-contact relations, asks and staged notices.
    crate::counterparty_contact::erase_trusted_contact_rows_in_txn,
    // FIX 11952: a TASK's comm receipt-import skip marker.
    crate::comm::erase_skipped_send_receipt_in_txn,
    #[cfg(feature = "sync")]
    crate::sync::selector::erase_carried_born_with_in_txn,
    // FIX 7998: retained federation and maintenance copies of the row.
    #[cfg(feature = "sync")]
    crate::sync::federation_burst::erase_retained_copies_in_txn,
];

/// Runs before the record's body and edges go. `physical` is false for a soft
/// erase, which keeps the shell's topology (redirects, claim reassignment).
pub(crate) fn tear_derived_rows_in_txn(
    store: &Store,
    wtxn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    physical: bool,
) -> Result<()> {
    // The symbol manifest and its revision index name the artifact's symbols
    // (H41).
    crate::code_symbol::delete_code_symbol_manifest_in_txn(store, wtxn, id)?;
    // Both contact index legs carry a hash of the counterparty (H105).
    crate::counterparty_contact::drop_contact_index_rows_in_txn(store, wtxn, id)?;
    for erase in ERASERS {
        erase(store, wtxn, id)?;
    }
    if physical {
        crate::identity_topology::forget_claim_reassignments_in_txn(store, wtxn, id)?;
        crate::identity_redirect::forget_deleted_in_txn(store, wtxn, id)?;
    }
    Ok(())
}
