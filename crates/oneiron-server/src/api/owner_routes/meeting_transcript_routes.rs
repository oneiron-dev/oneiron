//! Owner-selected storage, speaker labels and exact reads of meeting artifacts.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::blob_artifact::BLOB_ARTIFACT_CONTENT_HASH_LEN;
use oneiron::ingest::meeting_audio::{
    BulkImportBinding, MeetingTranscriptVersionPin, ProducedMeetingTranscript,
    StoredMeetingTranscript,
};
use serde::{Deserialize, Serialize};

use super::{OwnerReply, OwnerRoute, OwnerTable, RestShape, blocking, owner};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::owner::{OwnerError, OwnerResult, entity_id};
use crate::server::SyncServer;

mod import;

pub(super) fn owner_table() -> OwnerTable {
    let mut routes = vec![
        (
            OwnerRoute {
                method: "post",
                path: "/meeting-transcripts/persist",
                summary: "Store a meeting transcript bound to its selected source-audio version.",
                row: None,
                shape: Some(RestShape::json(persist_schema, stored_schema)),
            },
            post(persist),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/meeting-transcripts/label",
                summary: "Label a selected meeting transcript; labels are source strings, not PERSON identities.",
                row: None,
                shape: Some(RestShape::json(label_schema, stored_schema)),
            },
            post(label),
        ),
        (
            OwnerRoute {
                method: "post",
                path: "/meeting-transcripts/read",
                summary: "Read the exact selected meeting artifact after checking its source-audio relationship.",
                row: None,
                shape: Some(RestShape::json(read_schema, read_reply_schema)),
            },
            post(read),
        ),
    ];
    routes.extend(import::owner_table());
    routes
}

/// A native blob version selection, not an owner credential or import consent.
#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct VersionPin {
    /// Artifact id as 32 hex characters.
    artifact: String,
    version: u64,
    /// BLAKE3 of the selected version's bytes, as 64 hex characters.
    content_hash: String,
}

#[derive(Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct StoredTranscript {
    source_audio: VersionPin,
    transcript: VersionPin,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct PersistTranscript {
    source_audio: VersionPin,
    /// Exact oneiron.meeting_transcript.v1 artifact JSON, not flattened text.
    artifact_json: String,
    name: String,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct LabelTranscript {
    stored: StoredTranscript,
    /// speaker_cluster to source label; unmentioned clusters stay unchanged.
    labels: BTreeMap<String, String>,
}

#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ReadTranscript {
    stored: StoredTranscript,
}

#[derive(Serialize, schemars::JsonSchema)]
struct ReadReply {
    stored: StoredTranscript,
    artifact_json: String,
    recording_id: String,
    import_binding: BulkImportBinding,
}

fn persist_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<PersistTranscript>()
}

fn label_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<LabelTranscript>()
}

fn read_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ReadTranscript>()
}

fn stored_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<StoredTranscript>()
}

fn read_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<ReadReply>()
}

fn native_pin(field: &str, pin: &VersionPin) -> OwnerResult<MeetingTranscriptVersionPin> {
    let artifact = entity_id(&format!("{field}.artifact"), &pin.artifact)?;
    let invalid = || OwnerError::Invalid(format!("{field}.content_hash must be 64 hex characters"));
    let value = &pin.content_hash;
    if value.len() != BLOB_ARTIFACT_CONTENT_HASH_LEN * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    let mut content_hash = [0; BLOB_ARTIFACT_CONTENT_HASH_LEN];
    for (at, byte) in content_hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[at * 2..at * 2 + 2], 16).map_err(|_| invalid())?;
    }
    Ok(MeetingTranscriptVersionPin {
        artifact,
        version: pin.version,
        content_hash,
    })
}

fn native_stored(stored: &StoredTranscript) -> OwnerResult<StoredMeetingTranscript> {
    Ok(StoredMeetingTranscript {
        source_audio: native_pin("stored.source_audio", &stored.source_audio)?,
        transcript: native_pin("stored.transcript", &stored.transcript)?,
    })
}

impl From<&MeetingTranscriptVersionPin> for VersionPin {
    fn from(pin: &MeetingTranscriptVersionPin) -> Self {
        Self {
            artifact: pin.artifact.to_hex(),
            version: pin.version,
            content_hash: blake3::Hash::from_bytes(pin.content_hash)
                .to_hex()
                .to_string(),
        }
    }
}

impl From<&StoredMeetingTranscript> for StoredTranscript {
    fn from(stored: &StoredMeetingTranscript) -> Self {
        Self {
            source_audio: (&stored.source_audio).into(),
            transcript: (&stored.transcript).into(),
        }
    }
}

async fn persist(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<PersistTranscript>,
) -> OwnerReply<StoredTranscript> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let stored = blocking(move || {
        let source_audio = native_pin("source_audio", &request.source_audio)?;
        let transcript =
            ProducedMeetingTranscript::from_json(request.artifact_json).map_err(|error| {
                OwnerError::Invalid(format!(
                    "artifact_json is not a meeting transcript: {error}"
                ))
            })?;
        let stored = server.vault().persist_meeting_transcript_as_owner(
            &owner,
            &source_audio,
            &transcript,
            &request.name,
        )?;
        Ok(StoredTranscript::from(&stored))
    })
    .await?;
    Ok(Json(stored))
}

async fn label(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<LabelTranscript>,
) -> OwnerReply<StoredTranscript> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let stored = blocking(move || {
        let stored = native_stored(&request.stored)?;
        let labeled =
            server
                .vault()
                .label_meeting_transcript_as_owner(&owner, &stored, &request.labels)?;
        Ok(StoredTranscript::from(&labeled))
    })
    .await?;
    Ok(Json(stored))
}

async fn read(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    payload: OwnerJsonBody<ReadTranscript>,
) -> OwnerReply<ReadReply> {
    let owner = owner(&auth, &server)?;
    let request = payload.read(&server).await?;
    let reply = blocking(move || {
        let stored = native_stored(&request.stored)?;
        let transcript = server
            .vault()
            .read_meeting_transcript_as_owner(&owner, &stored)?;
        Ok(ReadReply {
            stored: StoredTranscript::from(&stored),
            artifact_json: transcript.json().to_owned(),
            recording_id: transcript.recording_id().to_owned(),
            import_binding: transcript
                .bulk_import_binding(&import_scope(server.vault()))
                .map_err(|error| OwnerError::Invalid(error.to_string()))?,
        })
    })
    .await?;
    Ok(Json(reply))
}

fn import_scope(vault: &oneiron::Vault) -> String {
    blake3::Hash::from_bytes(vault.vault_key_vault_id())
        .to_hex()
        .to_string()
}
