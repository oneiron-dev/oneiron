//! Native NOTE landing for an already-authorized meeting artifact.

use crate::edge::{EdgeActorClass, EdgeKind};
use crate::ingest::meeting_audio::{
    MEETING_TRANSCRIPT_NOTE_KIND, MeetingImportProvenance, MeetingTranscriptNoteOutcome,
};
use crate::ingest::{MEETING_TRANSCRIPT_SOURCE_ID, NormalizedIngestNote};
use crate::note::{ImportedNoteStanding, NoteKind};
use crate::write_envelope::WriteActor;
use crate::{EntityId, Error, Result, Vault};

impl Vault {
    pub(crate) fn land_meeting_transcript_note_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        importer: EntityId,
        source: &MeetingImportProvenance,
        note: &NormalizedIngestNote,
        at: u64,
    ) -> Result<MeetingTranscriptNoteOutcome> {
        let pin = &source.stored.transcript;
        let folder = format!(
            "{MEETING_TRANSCRIPT_SOURCE_ID}:{}:{}:{}",
            pin.artifact.to_hex(),
            pin.version,
            importer.to_hex(),
        );
        let id = Self::imported_note_id(&folder, &note.source_record_id)?;
        let raw = self.get_raw_in(txn, &id)?;
        let standing =
            if crate::deletion::row_deletion_marked(&self.store, txn, &id, raw.as_deref())?
                || self.archive_tombstone_in_txn(txn, &id)?.is_some()
            {
                Some(ImportedNoteStanding::Removed)
            } else if raw.is_some() {
                let (_, core) = super::super::verbs::note_core(self, txn, id)?;
                Some(
                    if core.source_revision_ref
                        == super::revision(&folder, &note.source_record_id, &note.text)
                    {
                        ImportedNoteStanding::Unchanged
                    } else {
                        ImportedNoteStanding::Changed
                    },
                )
            } else {
                None
            };
        if let Some(standing) = standing {
            return Ok(MeetingTranscriptNoteOutcome::Retained {
                note_ref: id,
                standing,
            });
        }
        super::super::validate_markdown(&note.text)?;
        super::super::document::validate_title(&note.title)?;
        let world = self
            .record_world_in_txn(txn, &pin.artifact)?
            .ok_or(Error::EntityNotFound)?;
        let kind = NoteKind::parse(MEETING_TRANSCRIPT_NOTE_KIND).ok_or(
            Error::InvariantViolation("meeting NOTE kind is not shipped"),
        )?;
        let notes = [super::ImportedNote {
            path: note.source_record_id.clone(),
            kind: MEETING_TRANSCRIPT_NOTE_KIND.to_owned(),
            title: Some(note.title.clone()),
            written_at: note.occurred_at.unwrap_or(at),
            markdown: note.text.clone(),
            original: None,
        }];
        let provenance_bytes = rmp_serde::to_vec_named(source)
            .map_err(|_| Error::InvariantViolation("meeting NOTE provenance encode"))?;
        let provenance = rmpv::decode::read_value(&mut provenance_bytes.as_slice())
            .map_err(|_| Error::InvariantViolation("meeting NOTE provenance decode"))?;
        self.land_imported_notes_from_source_in_txn(
            txn,
            importer,
            &folder,
            world,
            &notes,
            vec![kind],
            &[id],
            &[],
            MEETING_TRANSCRIPT_SOURCE_ID,
            Some(provenance),
        )?;
        let author = Self::imported_note_author(&folder)?;
        let mut content = crate::federation::ActorContentTxn::new(
            self,
            txn,
            WriteActor::new(author, EdgeActorClass::System),
            crate::core_write::CoreWriteLaneRef::Unbound,
        )?;
        content.apply_batch(
            self.batch_in()
                .edge(&id, EdgeKind::DerivedFrom, &pin.artifact, 1.0)
                .edge(
                    &id,
                    EdgeKind::DerivedFrom,
                    &source.stored.source_audio.artifact,
                    1.0,
                ),
        )?;
        content.finish()?;
        Ok(MeetingTranscriptNoteOutcome::Landed { note_ref: id })
    }
}
