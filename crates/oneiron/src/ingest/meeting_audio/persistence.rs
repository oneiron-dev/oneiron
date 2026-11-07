//! Owner-selected storage of exact meeting artifacts and source-label revisions.

use std::collections::BTreeMap;

use heed::RoTxn;

use crate::blob_artifact::{
    BLOB_ARTIFACT_CONTENT_HASH_LEN, BlobArtifactBody, BlobArtifactVersion, BlobVersionProvenance,
    encode_blob_artifact_body, read_blob_artifact_head_in_txn,
};
use crate::consent::AuthenticatedOwner;
use crate::core_write::CoreWriteLaneRef;
use crate::edge::EdgeActorClass;
use crate::registry::ENTITY_TYPE_BLOB_ARTIFACT;
use crate::write_envelope::WriteActor;
use crate::write_envelope::provenance::made_by::{
    MadeBy, MadeByClass, MadeByInput, MadeByInputRole, MadeByProcess,
};
use crate::{EntityId, Error, Result, TimeRange, Vault};

use super::ProducedMeetingTranscript;
use super::provenance::sha256;

/// A native version selection, not an owner credential or import consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeetingTranscriptVersionPin {
    pub artifact: EntityId,
    pub version: u64,
    pub content_hash: [u8; BLOB_ARTIFACT_CONTENT_HASH_LEN],
}

impl MeetingTranscriptVersionPin {
    fn from_version(artifact: EntityId, version: &BlobArtifactVersion) -> Self {
        Self {
            artifact,
            version: version.version,
            content_hash: version.content_hash,
        }
    }
}

/// Exact source-audio and transcript versions. The native version ledger
/// retains their relationship through the source version's claim in made_by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredMeetingTranscript {
    pub source_audio: MeetingTranscriptVersionPin,
    pub transcript: MeetingTranscriptVersionPin,
}

impl Vault {
    /// Read the exact selected artifact under a current owner proof. The
    /// source-audio version, ledger relationship and actual bytes are checked
    /// in this same native read transaction. The result still needs fresh
    /// exact-byte bulk import consent before it can become observations.
    pub fn read_meeting_transcript_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        stored: &StoredMeetingTranscript,
    ) -> Result<ProducedMeetingTranscript> {
        let txn = self.store.env.read_txn()?;
        owner.revalidate_in_txn(self, &txn)?;
        let (_, _, transcript) = stored_transcript(self, &txn, stored)?;
        Ok(transcript)
    }

    /// Save an owner's exact artifact, without importing its observations.
    /// The source audio must already be retained as the selected native blob
    /// version. Its actual bytes, not a recording label, bind this recording.
    pub fn persist_meeting_transcript_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        source_audio: &MeetingTranscriptVersionPin,
        transcript: &ProducedMeetingTranscript,
        name: &str,
    ) -> Result<StoredMeetingTranscript> {
        let actor = WriteActor::new(owner.revalidate(self)?, EdgeActorClass::Human);
        let artifact = self.new_entity_id()?;
        self.try_with_actor_content_write_txn(actor, CoreWriteLaneRef::Unbound, |content| {
            owner.revalidate_in_txn(self, content.read())?;
            let (source_version, audio) = pinned_version(self, content.read(), source_audio)?;
            check_source_audio(transcript, &audio)?;
            let source_body = self
                .get_blob_artifact_in_txn(content.read(), &source_audio.artifact)?
                .ok_or(Error::EntityNotFound)?;
            let body = BlobArtifactBody::new(name, "application/json")
                .with_secret_taint_refs(source_body.secret_taint_refs);
            let data = encode_blob_artifact_body(&body)?;
            let at = self.instant_in_txn(content.read())?.secs();
            let occurred = TimeRange { start: at, end: at };
            content.apply_batch(self.batch_in().put(
                &artifact,
                ENTITY_TYPE_BLOB_ARTIFACT,
                occurred,
                at,
                &data,
            ))?;
            let made_by = storage_provenance(actor, &[source_version.claim_id], transcript, at);
            let version = content.update_artifact(artifact, |txn, _lane| {
                self.append_blob_artifact_version_made_by_in_txn(
                    txn,
                    &artifact,
                    None,
                    transcript.json().as_bytes(),
                    &BlobVersionProvenance::UserUpload,
                    &made_by,
                    actor,
                    occurred,
                    at,
                )
            })?;
            Ok(StoredMeetingTranscript {
                source_audio: source_audio.clone(),
                transcript: MeetingTranscriptVersionPin::from_version(artifact, &version),
            })
        })
    }

    /// Label the selected stored version as the authenticated owner. Labels
    /// remain source strings, not PERSON references or voice enrollment.
    /// A newer head is preserved: the changed copy explicitly forks from
    /// the selected base instead of silently parenting the newer content.
    pub fn label_meeting_transcript_as_owner(
        &self,
        owner: &AuthenticatedOwner,
        stored: &StoredMeetingTranscript,
        labels: &BTreeMap<String, String>,
    ) -> Result<StoredMeetingTranscript> {
        let actor = WriteActor::new(owner.revalidate(self)?, EdgeActorClass::Human);
        self.try_with_actor_content_write_txn(actor, CoreWriteLaneRef::Unbound, |content| {
            content.update_artifact(stored.transcript.artifact, |txn, _lane| {
                owner.revalidate_in_txn(self, txn)?;
                let (base, source, transcript) = stored_transcript(self, txn, stored)?;
                let labeled = transcript
                    .with_speaker_labels(labels)
                    .map_err(|_| Error::InvalidClaimBody("invalid meeting speaker labels"))?;
                if labeled.json() == transcript.json() {
                    return Ok(stored.clone());
                }
                let current =
                    read_blob_artifact_head_in_txn(&self.store, txn, &stored.transcript.artifact)?;
                let fork_parent = (current.as_ref() != Some(&base)).then_some(base.version);
                let at = self.instant_in_txn(txn)?.secs();
                let made_by =
                    storage_provenance(actor, &[source.claim_id, base.claim_id], &labeled, at);
                let version = self.append_blob_artifact_version_made_by_in_txn(
                    txn,
                    &stored.transcript.artifact,
                    fork_parent,
                    labeled.json().as_bytes(),
                    &BlobVersionProvenance::UserUpload,
                    &made_by,
                    actor,
                    TimeRange { start: at, end: at },
                    at,
                )?;
                Ok(StoredMeetingTranscript {
                    source_audio: stored.source_audio.clone(),
                    transcript: MeetingTranscriptVersionPin::from_version(
                        stored.transcript.artifact,
                        &version,
                    ),
                })
            })
        })
    }
}

fn stored_transcript(
    vault: &Vault,
    txn: &RoTxn<'_>,
    stored: &StoredMeetingTranscript,
) -> Result<(
    BlobArtifactVersion,
    BlobArtifactVersion,
    ProducedMeetingTranscript,
)> {
    let (base, bytes) = pinned_version(vault, txn, &stored.transcript)?;
    let (source, audio) = pinned_version(vault, txn, &stored.source_audio)?;
    if !base
        .made_by
        .inputs
        .iter()
        .any(|input| input.row == source.claim_id && input.role == MadeByInputRole::Input)
    {
        return Err(Error::InvalidClaimBody(
            "transcript version does not name this source-audio version",
        ));
    }
    let json = String::from_utf8(bytes)
        .map_err(|_| Error::InvalidClaimBody("meeting artifact is not UTF-8"))?;
    let transcript = ProducedMeetingTranscript::from_json(json)
        .map_err(|_| Error::InvalidClaimBody("invalid stored meeting artifact"))?;
    check_source_audio(&transcript, &audio)?;
    Ok((base, source, transcript))
}

fn pinned_version(
    vault: &Vault,
    txn: &RoTxn<'_>,
    pin: &MeetingTranscriptVersionPin,
) -> Result<(BlobArtifactVersion, Vec<u8>)> {
    vault
        .get_blob_artifact_in_txn(txn, &pin.artifact)?
        .ok_or(Error::EntityNotFound)?;
    let version = vault
        .blob_artifact_version_metadata_in_txn(txn, &pin.artifact, pin.version)?
        .ok_or(Error::EntityNotFound)?;
    if version.content_hash != pin.content_hash {
        return Err(Error::InvalidClaimBody("meeting blob version pin changed"));
    }
    let bytes = vault
        .read_blob_artifact_version_in_txn(txn, &pin.artifact, pin.version)?
        .ok_or(Error::EntityNotFound)?;
    if blake3::hash(&bytes).as_bytes() != &version.content_hash {
        return Err(Error::CorruptedIndex("meeting blob version content hash"));
    }
    Ok((version, bytes))
}

fn check_source_audio(transcript: &ProducedMeetingTranscript, audio: &[u8]) -> Result<()> {
    let document: serde_json::Value = serde_json::from_str(transcript.json())
        .map_err(|_| Error::InvalidClaimBody("invalid meeting artifact JSON"))?;
    let hash = sha256(audio);
    if document["recording"]["source_sha256"].as_str() != Some(hash.as_str())
        || transcript.recording_id() != format!("sha256:{hash}")
    {
        return Err(Error::InvalidClaimBody(
            "meeting artifact does not bind the selected source-audio bytes",
        ));
    }
    Ok(())
}

/// Records the owner's storage/label action, not ASR execution or factual
/// approval. Inference receipts stay in the exact artifact; importing it
/// still uses the existing Imported/Proposed and bulk-consent doors.
fn storage_provenance(
    actor: WriteActor,
    inputs: &[EntityId],
    transcript: &ProducedMeetingTranscript,
    at: u64,
) -> MadeBy {
    MadeBy {
        inputs: inputs
            .iter()
            .map(|row| MadeByInput {
                row: *row,
                role: MadeByInputRole::Input,
            })
            .collect(),
        process: MadeByProcess {
            actor: actor.entity_ref(),
            class: MadeByClass::Stated,
            identity: "meeting_transcript.storage".to_owned(),
            version: "1".to_owned(),
            params_hash: sha256(transcript.json().as_bytes()),
        },
        at,
        trigger: None,
    }
}
