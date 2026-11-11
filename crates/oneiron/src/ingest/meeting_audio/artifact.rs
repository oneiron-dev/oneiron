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
        let artifact = Self::from_json(json)?;
        if artifact.recording_id != recording_id {
            return Err(AudioError::Serialization);
        }
        Ok(artifact)
    }

    /// Recover the exact saved artifact bytes for a later authenticated bulk
    /// consent decision. This validates through the real consumer and derives
    /// the binding from the document, never from caller-supplied turn IDs.
    pub fn from_json(json: String) -> AudioResult<Self> {
        let normalized = INGEST_SOURCE_REGISTRY.normalize(MEETING_TRANSCRIPT_SOURCE_ID, &json)?;
        let value: serde_json::Value =
            serde_json::from_str(&json).map_err(|_| AudioError::Serialization)?;
        let recording_id = value["recording"]["recording_id"]
            .as_str()
            .filter(|id| !id.trim().is_empty())
            .ok_or(AudioError::Serialization)?
            .to_owned();
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

    /// Return a separate artifact with the supplied cluster labels. These are
    /// source labels, not authenticated PERSON identities or voice enrollment.
    /// Unmentioned clusters and existing labels stay unchanged. Import consent
    /// still binds the exact returned artifact bytes, not the original artifact.
    pub fn with_speaker_labels(
        &self,
        labels: &std::collections::BTreeMap<String, String>,
    ) -> AudioResult<Self> {
        let mut document: serde_json::Value =
            serde_json::from_str(&self.json).map_err(|_| AudioError::Serialization)?;
        let turns = document["turns"]
            .as_array_mut()
            .ok_or(AudioError::Serialization)?;
        let mut changed = false;
        for turn in turns {
            let label = turn["speaker_cluster"]
                .as_str()
                .and_then(|cluster| labels.get(cluster));
            if let Some(label) = label
                && turn["speaker_ref"].as_str() != Some(label.as_str())
            {
                turn.as_object_mut()
                    .ok_or(AudioError::Serialization)?
                    .insert(
                        "speaker_ref".to_owned(),
                        serde_json::Value::String(label.clone()),
                    );
                changed = true;
            }
        }
        if !changed {
            return Ok(self.clone());
        }
        let json = serde_json::to_string(&document).map_err(|_| AudioError::Serialization)?;
        Self::new(json, self.recording_id.clone())
    }

    /// Describe the complete immutable artifact an authenticated host asks
    /// the owner to import. This description alone grants no import consent.
    pub fn bulk_import_binding(&self, vault_scope: &str) -> AudioResult<BulkImportBinding> {
        if vault_scope.trim().is_empty() {
            return Err(AudioError::BulkConsentMismatch);
        }
        Ok(BulkImportBinding {
            vault_scope: vault_scope.to_owned(),
            source_id: MEETING_TRANSCRIPT_SOURCE_ID.to_owned(),
            recording_id: self.recording_id.clone(),
            artifact_sha256: sha256(self.json.as_bytes()),
            source_record_ids: self.source_record_ids.clone(),
        })
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
        let binding = self.bulk_import_binding(authorizer.vault_scope())?;
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
