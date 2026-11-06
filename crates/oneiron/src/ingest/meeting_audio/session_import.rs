//! Owner-bound import of exact stored meeting turns into one native SESSION.

use crate::calendar::transcript::{TranscriptFileDropRequest, TranscriptIngestOutcome};
use crate::consent::AuthenticatedOwner;
use crate::ingest::NormalizedIngestNote;
use crate::session_lifecycle::SessionKey;
use crate::{Error, Vault};

use super::session_source::MeetingImportProvenance;
use super::{AudioError, BulkImportAuthorizer, BulkImportReceipt, StoredMeetingTranscript};

#[derive(Debug, thiserror::Error)]
pub enum MeetingTranscriptImportError {
    #[error(transparent)]
    Storage(#[from] Error),
    #[error(transparent)]
    Audio(#[from] AudioError),
}

/// A native `Session` outcome names committed observations; `RetryOpenSession`
/// names the existing busy sitting. The normalized fallback is retained input
/// for a source-trust-aware NOTE door, not a landed NOTE.
#[derive(Debug)]
pub struct MeetingTranscriptImportOutcome {
    pub session: Option<TranscriptIngestOutcome>,
    pub pending_note_fallback: Option<NormalizedIngestNote>,
    pub stored: StoredMeetingTranscript,
    pub bulk_receipt: BulkImportReceipt,
}

impl Vault {
    /// Authenticate the owner, obtain fresh consent for the selected exact
    /// artifact, then recheck both native pins and bytes in the committing
    /// writer. Storage and consent do not confirm ASR facts or speaker identity.
    ///
    /// A busy caller sitting returns the native RetryOpenSession outcome;
    /// no second SESSION or fabricated NOTE is created. A later invocation
    /// asks for fresh consent rather than replaying this method's receipt.
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
        let session = self.with_write_txn_grouped(|txn| {
            let actor = owner.revalidate_in_txn(self, txn)?;
            let (version, _, current) = super::persistence::stored_transcript(self, txn, stored)?;
            if current.json() != authorized.artifact().json() {
                return Err(Error::InvalidClaimBody(
                    "meeting artifact changed during consent",
                ));
            }
            if input.transcript.turns.is_empty() {
                return Ok(None);
            }
            // Arrival is this native writer's clock, not an ASR timestamp or
            // a caller-provided observation time. Claimed offsets stay exact.
            let arrived_at_ms = self
                .instant_in_write_txn(txn)?
                .secs()
                .checked_mul(1_000)
                .ok_or(Error::InvariantViolation("meeting import arrival overflow"))?;
            let machine = crate::identity::load_or_mint_machine_id_in_txn(self, txn)?;
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
            )
            .map(Some)
        })?;
        Ok(MeetingTranscriptImportOutcome {
            session,
            pending_note_fallback: input.note_fallback,
            stored: stored.clone(),
            bulk_receipt: authorized.receipt().clone(),
        })
    }
}
