//! `PUT /v1/owner/coach/training-checkpoints` (FIX 12086): the owner's
//! starting checkpoint into custody, however large. The body is the
//! checkpoint's files as raw bytes, back to back, never one base64 JSON
//! document; the `x-oneiron-checkpoint` header names them. The body spools
//! to the vault's disk as it arrives, under the disk floor uploads keep
//! (`limits.disk_reserve_bytes`), and its length never refuses it. The
//! engine then keeps the files from the spool one at a time.
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use oneiron::llm::ModelId;
use oneiron::training_pack::{
    CheckpointFileKind, CheckpointFileStream, CheckpointStream, PinnedCheckpoint, SourcePin,
};
use serde::Deserialize;

use super::super::super::{OwnerReply, blocking, owner};
use crate::api::body_spool::{self, SpoolPolicy, Unspooled};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::owner::OwnerResult;
use crate::server::SyncServer;

/// The request header that carries the checkpoint's manifest, as JSON.
pub(crate) const CHECKPOINT_HEADER: &str = "x-oneiron-checkpoint";

/// The checkpoint a `PUT` streams: its model, and each file in the order its
/// bytes follow one another in the body.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub(crate) struct CheckpointManifest {
    /// The model the files load as, `provider/name@revision`.
    model: ModelId,
    files: Vec<ManifestFile>,
}

/// One file of the body.
#[derive(Debug, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct ManifestFile {
    /// A relative name; weights are `.safetensors`.
    name: String,
    kind: CheckpointFileKind,
    /// The repository and immutable revision the file comes from.
    source: SourcePin,
    /// The producer's BLAKE3 of the file, as 64 hex.
    blake3: String,
    /// The file's length in bytes.
    bytes: u64,
}

/// `PUT /v1/owner/coach/training-checkpoints`: the owner's starting
/// checkpoint into custody. The owner door runs first, then the header is
/// read, then the body is spooled; the engine keeps every file or none. The
/// answer is the pinned checkpoint a training draft names as its
/// `starting_checkpoint`.
pub(super) async fn keep_checkpoint(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    body: Body,
) -> OwnerReply<PinnedCheckpoint> {
    let owner = owner(&auth, &server)?;
    let checkpoint = manifest(&headers)?;
    let spool = body_spool::spool_then(
        &server,
        body_spool::declared_length(&headers),
        body,
        SpoolPolicy::custody(&server),
        |spool| spool,
    )
    .await
    .map_err(Unspooled::refusal)?;
    let pinned = blocking(move || -> OwnerResult<PinnedCheckpoint> {
        let mut spool = spool;
        Ok(server.vault().keep_training_checkpoint_streamed(
            &owner,
            &checkpoint,
            &mut spool.reader(),
        )?)
    })
    .await?;
    Ok(Json(pinned))
}

/// The `x-oneiron-checkpoint` header as the engine's stream of files.
fn manifest(headers: &HeaderMap) -> Result<CheckpointStream, ApiError> {
    let refused = |reason: &str| {
        ApiError::bad_request(
            format!("{CHECKPOINT_HEADER}: {reason}"),
            Some(CHECKPOINT_HEADER),
        )
    };
    let manifest: CheckpointManifest = headers
        .get(CHECKPOINT_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| serde_json::from_str(value).ok())
        .ok_or_else(|| refused("expected the checkpoint's manifest as JSON"))?;
    let files = manifest
        .files
        .into_iter()
        .map(|file| -> Result<CheckpointFileStream, ApiError> {
            let blake3 = blake3::Hash::from_hex(&file.blake3)
                .map_err(|_| refused("each file's blake3 must be 64 hex"))?;
            Ok(CheckpointFileStream {
                name: file.name,
                kind: file.kind,
                source: file.source,
                blake3: *blake3.as_bytes(),
                bytes: file.bytes,
            })
        })
        .collect::<Result<Vec<_>, ApiError>>()?;
    Ok(CheckpointStream {
        model: manifest.model,
        files,
    })
}
