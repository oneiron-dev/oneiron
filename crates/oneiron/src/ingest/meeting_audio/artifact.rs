//! Immutable producer artifact and one approval for the complete import batch.

use crate::claim::{ClaimApprovalStatus, ClaimSource};
use crate::ingest::{INGEST_SOURCE_REGISTRY, MEETING_TRANSCRIPT_SOURCE_ID, NormalizedIngestBatch};

use super::provenance::sha256;
use super::{AudioError, AudioResult, BulkImportAuthorizer, BulkImportBinding, BulkImportReceipt};

/// Generation does not import or grant authority. Exporting the artifact is
/// harmless to the Gate: the existing source remains Imported/Proposed.
#[derive(Debug, Clone)]
pub struct ProducedMeetingTranscript {
    json: String,
    recording_id: String,
    source_record_ids: Vec<String>,
}

impl ProducedMeetingTranscript {
    pub(super) fn new(json: String, recording_id: String) -> AudioResult<Self> {
        // Exercise the real consumer rather than maintaining a second schema
        // validator. This is pure normalization, not import admission.
        let normalized = INGEST_SOURCE_REGISTRY.normalize(MEETING_TRANSCRIPT_SOURCE_ID, &json)?;
        let source_record_ids = normalized
            .records
            .into_iter()
            .map(|r| r.source_record_id)
            .collect();
        Ok(Self {
            json,
            recording_id,
            source_record_ids,
        })
    }

    pub fn json(&self) -> &str {
        &self.json
    }

    pub fn recording_id(&self) -> &str {
        &self.recording_id
    }

    /// Approve the complete immutable artifact once, then hand it to the
    /// existing normalizer. No per-turn prompts or transcript-supplied grant.
    /// A host authorizer must authenticate the owner, resolve pending consent,
    /// and retain the receipt; this trait is not a new persisted consent system.
    /// Borrowing preserves the artifact for retries after pending/denied consent;
    /// a retry never requires another decode or inference run.
    pub fn authorize_import<A: BulkImportAuthorizer + ?Sized>(
        &self,
        authorizer: &mut A,
    ) -> AudioResult<AuthorizedMeetingImport> {
        let vault_scope = authorizer.vault_scope().to_owned();
        if vault_scope.trim().is_empty() {
            return Err(AudioError::BulkConsentMismatch);
        }
        let binding = BulkImportBinding {
            vault_scope,
            source_id: MEETING_TRANSCRIPT_SOURCE_ID.to_owned(),
            recording_id: self.recording_id.clone(),
            artifact_sha256: sha256(self.json.as_bytes()),
            source_record_ids: self.source_record_ids.clone(),
        };
        let receipt = authorizer
            .authorize_import(&binding)?
            .ok_or(AudioError::BulkConsentRequired)?;
        if receipt.binding != binding || receipt.receipt_ref.trim().is_empty() {
            return Err(AudioError::BulkConsentMismatch);
        }
        let normalized =
            INGEST_SOURCE_REGISTRY.normalize(MEETING_TRANSCRIPT_SOURCE_ID, &self.json)?;
        Ok(AuthorizedMeetingImport {
            artifact: self.clone(),
            normalized,
            receipt,
        })
    }
}

/// An authorized evidence batch, NOT authorization for automatic claim writes
/// or enrollment. Downstream extraction still uses imported admission/Gate.
#[derive(Debug)]
pub struct AuthorizedMeetingImport {
    artifact: ProducedMeetingTranscript,
    normalized: NormalizedIngestBatch,
    receipt: BulkImportReceipt,
}

impl AuthorizedMeetingImport {
    pub fn artifact(&self) -> &ProducedMeetingTranscript {
        &self.artifact
    }

    pub fn normalized(&self) -> &NormalizedIngestBatch {
        &self.normalized
    }

    pub fn receipt(&self) -> &BulkImportReceipt {
        &self.receipt
    }

    pub fn claim_source(&self) -> ClaimSource {
        ClaimSource::Imported
    }

    pub fn default_admission(&self) -> ClaimApprovalStatus {
        ClaimApprovalStatus::Proposed
    }

    pub fn into_parts(
        self,
    ) -> (
        ProducedMeetingTranscript,
        NormalizedIngestBatch,
        BulkImportReceipt,
    ) {
        (self.artifact, self.normalized, self.receipt)
    }
}
