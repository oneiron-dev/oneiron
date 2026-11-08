//! Owner-bound import of exact stored meeting turns into one native SESSION.

use crate::calendar::transcript::{TranscriptFileDropRequest, TranscriptIngestOutcome};
use crate::consent::AuthenticatedOwner;
use crate::session_lifecycle::SessionKey;
use crate::{Error, Vault};

use super::session_source::MeetingImportProvenance;
use super::{
    AudioError, BulkImportAuthorizer, BulkImportReceipt, MeetingTranscriptNoteOutcome,
    StoredMeetingTranscript,
};

#[derive(Debug, thiserror::Error)]
pub enum MeetingTranscriptImportError {
    #[error(transparent)]
    Storage(#[from] Error),
    #[error(transparent)]
    Audio(#[from] AudioError),
}

/// A native `Session` outcome names landed observations; `RetryOpenSession`
/// names the existing busy sitting. The NOTE outcome separately reports a
/// landed fallback or the standing of an earlier import of this version.
#[derive(Debug)]
pub struct MeetingTranscriptImportOutcome {
    pub session: Option<TranscriptIngestOutcome>,
    pub note_fallback: Option<MeetingTranscriptNoteOutcome>,
    pub stored: StoredMeetingTranscript,
    pub bulk_receipt: BulkImportReceipt,
}

impl Vault {
    /// Authenticate the owner, obtain fresh consent for the selected exact
    /// artifact, then recheck both native pins and bytes in the committing
    /// writer. Storage and consent do not confirm ASR facts or speaker identity.
    ///
    /// A busy caller sitting returns the native RetryOpenSession outcome;
    /// no second SESSION is created. Its normalized NOTE fallback lands in
    /// the same writer, with native Imported trust and no second approval.
    /// A later invocation asks for fresh consent rather than replaying this
    /// method's receipt; a NOTE from this version is not imported twice.
    pub fn import_meeting_transcript_as_owner<A: BulkImportAuthorizer + ?Sized>(
        &self,
        owner: &AuthenticatedOwner,
        stored: &StoredMeetingTranscript,
        authorizer: &mut A,
    ) -> Result<MeetingTranscriptImportOutcome, MeetingTranscriptImportError> {
        let artifact = self.read_meeting_transcript_as_owner(owner, stored)?;
        // Host callbacks run outside the LMDB writer. The private authorized
        // value comes only from the exact-byte bulk-consent boundary.
        let authorized = artifact.authorize_import(authorizer)?;
        let input = authorized.artifact().session_input()?;
        let source = MeetingImportProvenance {
            stored: stored.clone(),
            receipt: authorized.receipt().clone(),
        };
        let (session, note_fallback) = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let (version, _, current) = super::persistence::stored_transcript(self, txn, stored)?;
            if current.json() != authorized.artifact().json() {
                return Err(Error::InvalidClaimBody(
                    "meeting artifact changed during consent",
                ));
            }
            // Arrival is this native writer's clock, not an ASR timestamp or
            // a caller-provided observation time. Claimed offsets stay exact.
            let arrived_at_ms = self
                .instant_in_write_txn(txn)?
                .secs()
                .checked_mul(1_000)
                .ok_or(Error::InvariantViolation("meeting import arrival overflow"))?;
            let session = if input.transcript.turns.is_empty() {
                None
            } else {
                let machine = crate::identity::load_or_mint_machine_id_in_txn(self, txn)?;
                Some(
                    crate::calendar::transcript::ingest_meeting_transcript_in_txn(
                        self,
                        txn,
                        TranscriptFileDropRequest {
                            source_blob_ref: stored.transcript.artifact,
                            decoded_text: authorized.artifact().json(),
                            arrived_at_ms,
                        },
                        &input.transcript,
                        SessionKey { actor, machine },
                        &version,
                        &source,
                    )?,
                )
            };
            let note_fallback = input
                .note_fallback
                .as_ref()
                .map(|note| {
                    self.land_meeting_transcript_note_in_txn(
                        txn,
                        actor,
                        &source,
                        note,
                        arrived_at_ms / 1_000,
                    )
                })
                .transpose()?;
            Ok((session, note_fallback))
        })?;
        Ok(MeetingTranscriptImportOutcome {
            session,
            note_fallback,
            stored: stored.clone(),
            bulk_receipt: authorized.receipt().clone(),
        })
    }
}
