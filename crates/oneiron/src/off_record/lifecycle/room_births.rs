//! What a room write stages beside its row (FIX 4280, 4281; Engine 10-22):
//! the row's birth and, for a NOTE, its document's birth, in the segment and
//! on the transaction that stage the row, so each commits or aborts with it.
//!
//! Both are the room's bookkeeping. A birth spends none of the room's byte
//! budget (`session_overlay::keyspace::unbudgeted_row`); a NOTE's document,
//! which repeats text its row already holds, is marked as the write's own
//! bookkeeping before it is put, so a room at its limit takes exactly the
//! NOTE it took before (N2). The host's own memory accounting still counts
//! their bytes. Neither is a journal entry, so no promote or save replays
//! them, and both evaporate at close with the room.

use heed::RwTxn;

use super::session::OffRecordSession;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ports::{DocumentRowStore, DocumentSlot, EntityStoreRead};
use crate::provenance::birth::RowBirth;
use crate::provenance::birth::room::{SuppliedEvidence, stamp_room_birth_in_txn};
use crate::provenance::made_by::MadeByClass;
use crate::scan_check::EngineScan;
use crate::session_overlay::OverlayKeyspace;
use crate::side_table::{self, SideKey};
use crate::store::SessionStoreView;
use crate::write_envelope::{WriteActor, WriteEnvelope};

/// The door identity of a claim a room's run stages for its executor
/// (`OffRecordSession::stage_session_claim`).
const STAGED_CLAIM_DOOR: &str = "off_record.claims.stage";

/// The door identity of a claim a room derives from its sources
/// (`OffRecordSession::stage_session_derived_claim`).
const DERIVED_CLAIM_DOOR: &str = "off_record.claims.derive";

/// What a room write stages beside its row: who wrote it, its class, the
/// door it came in by and when, the rows it derives from, the evidence its
/// caller supplied, and whether it is a NOTE whose document is born with it.
pub(crate) struct RoomRowAttachments {
    actor: WriteActor,
    class: MadeByClass,
    door: &'static str,
    at: u64,
    sources: Vec<EntityId>,
    evidence: Vec<SuppliedEvidence>,
    note_document: bool,
}

impl RoomRowAttachments {
    /// A NOTE `actor` wrote through `door` at `at`, naming `evidence` as its
    /// caller supplied it: its document is born beside it.
    pub(crate) fn note(
        actor: WriteActor,
        door: &'static str,
        evidence: Vec<SuppliedEvidence>,
        at: u64,
    ) -> Self {
        Self {
            actor,
            class: MadeByClass::of_writer(actor.actor_class()),
            door,
            at,
            sources: Vec::new(),
            evidence,
            note_document: true,
        }
    }

    /// A claim of `envelope`'s actor and source, written through `door` at
    /// `at`, naming `evidence` as its caller supplied it.
    pub(crate) fn claim(
        envelope: &WriteEnvelope,
        door: &'static str,
        evidence: Vec<SuppliedEvidence>,
        at: u64,
    ) -> Self {
        Self {
            actor: envelope.actor(),
            class: MadeByClass::of_source(envelope.source()),
            door,
            at,
            sources: Vec::new(),
            evidence,
            note_document: false,
        }
    }

    /// A claim a room's run stages for its executor, of `envelope`'s actor
    /// and source, at `at`; its caller supplied no evidence.
    pub(crate) fn staged_claim(envelope: &WriteEnvelope, at: u64) -> Self {
        Self::claim(envelope, STAGED_CLAIM_DOOR, Vec::new(), at)
    }

    /// A claim the room derives from each of `sources`, of `envelope`'s
    /// actor and source, at `at`: its inputs are those sources, as the
    /// staging transaction reads them.
    pub(crate) fn derived_claim(envelope: &WriteEnvelope, sources: &[EntityId], at: u64) -> Self {
        Self {
            sources: sources.to_vec(),
            ..Self::claim(envelope, DERIVED_CLAIM_DOOR, Vec::new(), at)
        }
    }
}

impl OffRecordSession<'_> {
    /// Stages `attachments` beside `row`, a row the segment's transaction
    /// `wtxn` has just staged: a NOTE's document birth, then the row's birth,
    /// each read on a fresh view of the room so it sees the row.
    ///
    /// # Errors
    ///
    /// A stored NOTE body that does not decode; storage errors. A caller's
    /// evidence never refuses here, and a row stamped before keeps its first
    /// birth ([`stamp_room_birth_in_txn`]).
    pub(super) fn stage_row_attachments(
        &self,
        wtxn: &mut RwTxn<'_>,
        row: EntityId,
        attachments: &RoomRowAttachments,
    ) -> Result<()> {
        let view = self.read_view()?;
        if attachments.note_document {
            self.stage_note_document(&view, wtxn, row)?;
        }
        let mut inputs = Vec::with_capacity(attachments.sources.len());
        for source in &attachments.sources {
            if let Some(raw) = view.port_entity_raw(&*wtxn, source)? {
                inputs.push((*source, raw));
            }
        }
        let birth = RowBirth::in_room(
            attachments.actor,
            attachments.class,
            attachments.door,
            &inputs,
            &attachments.evidence,
            attachments.at,
        );
        stamp_room_birth_in_txn(&view, wtxn, &row, &birth)
    }

    /// Stages the document birth of `note`, the NOTE row `view`'s room has
    /// just staged: its snapshot and state vector, each marked as the
    /// write's bookkeeping before it is put (N2). Its body's bytes are
    /// measured against their threshold row, the check waiting with the
    /// room ([`Self::pending_scan_checks`]); no size refuses it (rule 5).
    fn stage_note_document(
        &self,
        view: &SessionStoreView<'_>,
        wtxn: &mut RwTxn<'_>,
        note: EntityId,
    ) -> Result<()> {
        let Some(document) =
            crate::note::room_birth_document_in_txn(self.vault, view, &*wtxn, note)?
        else {
            return Ok(());
        };
        crate::note::measure_note_document(
            view,
            &*wtxn,
            EngineScan::NoteDocumentBytes,
            note,
            document.body_bytes,
            self.pending_scan_checks(),
        )?;
        let slot = DocumentSlot::of(note);
        let overlay = self.overlay();
        for prefix in [
            side_table::DOCUMENT_SNAPSHOT.prefix,
            side_table::DOCUMENT_STATE_VECTOR.prefix,
        ] {
            let mut key = prefix.to_vec();
            slot.encode_into(&mut key);
            overlay.mark_bookkeeping_row(OverlayKeyspace::SyncState, &key)?;
        }
        view.port_document_snapshot_put(wtxn, slot, &document.snapshot)?;
        view.port_document_state_vector_put(wtxn, slot, &document.state_vector)
    }
}
