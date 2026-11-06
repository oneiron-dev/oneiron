//! Temporary byte staging shared by the facade codec and receipt reader.

use std::fs::File;
use std::io;

use axum::body::{Body, Bytes};
use axum::http::HeaderMap;
use futures_util::StreamExt as _;
use oneiron::sync::transport::CODEC_MIN_FRAME_BYTES;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

use crate::error::ApiError;

/// The ordinary facade calls whose bytes may leave the in-memory codec.
pub(super) fn facade_staged(verb: &str, headers: &HeaderMap) -> bool {
    !headers.contains_key(crate::api::write_facet::SESSION_HEADER)
        && !verb.split('.').any(|part| part == "off_record")
        && !matches!(
            verb,
            "ai.anonymous_chat"
                | "vault.secrets.register"
                | "vault.secrets.rotate"
                | "vault.secrets.custody.submit"
                | "vault.notes.editor.close"
        )
}

/// Input failures retain each caller's existing body-read error mapping.
pub(super) enum StageError {
    Input,
    TooLarge,
    Io,
    Stopped,
}

/// Reads the arrival to a capped, anonymous file before any blocking decoder.
pub(super) async fn stage(body: Body, cap: usize) -> Result<(File, usize), StageError> {
    let file = tokio::task::spawn_blocking(tempfile::tempfile)
        .await
        .map_err(|_| StageError::Stopped)?
        .map_err(|_| StageError::Io)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut frames = body.into_data_stream();
    let mut length = 0usize;
    while let Some(frame) = frames.next().await {
        let frame = frame.map_err(|_| StageError::Input)?;
        if frame.len() > cap - length {
            return Err(StageError::TooLarge);
        }
        length += frame.len();
        file.write_all(&frame).await.map_err(|_| StageError::Io)?;
    }
    file.rewind().await.map_err(|_| StageError::Io)?;
    Ok((file.into_std().await, length))
}

/// The same staged bytes, owned by the async response/request body reader.
pub(super) fn replay(file: File) -> Body {
    Body::from_stream(futures_util::stream::try_unfold(
        tokio::fs::File::from_std(file),
        |mut file| async move {
            let mut piece = vec![0; CODEC_MIN_FRAME_BYTES];
            let read = file.read(&mut piece).await?;
            if read == 0 {
                return Ok::<_, io::Error>(None);
            }
            piece.truncate(read);
            Ok(Some((Bytes::from(piece), file)))
        },
    ))
}

pub(super) fn staging_failed() -> ApiError {
    ApiError::internal_server_error("the request body could not be staged")
}

pub(super) fn worker_stopped() -> ApiError {
    ApiError::internal_server_error("the request body decoder stopped")
}
