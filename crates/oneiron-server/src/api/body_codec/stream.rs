//! Ordinary compressed facade requests, staged before the route reads them.

use std::fs::File;
use std::io::{self, BufReader, Read, Seek, Write};

use axum::body::{Body, Bytes};
use axum::extract::Request;
use futures_util::StreamExt as _;
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _, AsyncWriteExt as _};

use super::{Codec, MIN_ENCODED_BYTES, too_large};
use crate::error::ApiError;

/// Ephemeral and custody calls keep the codec's existing in-memory path.
/// A held room NOTE's editor close need not carry its session header.
pub(super) fn stages(request: &Request) -> bool {
    let Some(verb) = request.uri().path().strip_prefix("/v1/core/facade/") else {
        return false;
    };
    !request
        .headers()
        .contains_key(crate::api::write_facet::SESSION_HEADER)
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

/// Both encoded and decoded lengths meet the same ceiling as the RAM path.
/// Decoding finishes before dispatch, so a malformed stream is still a codec
/// refusal, not a partial request reaching the receipt or the JSON reader.
pub(super) async fn decode_body(
    body: Body,
    codec: Codec,
    cap: usize,
) -> Result<(Body, u64), ApiError> {
    let file = tokio::task::spawn_blocking(tempfile::tempfile)
        .await
        .map_err(|_| decoder_stopped())?
        .map_err(spool_failed)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut frames = body.into_data_stream();
    let mut length = 0usize;
    while let Some(frame) = frames.next().await {
        let frame = frame.map_err(|_| too_large(cap))?;
        if frame.len() > cap - length {
            return Err(too_large(cap));
        }
        length += frame.len();
        file.write_all(&frame).await.map_err(spool_failed)?;
    }
    if length == 0 {
        return Ok((Body::empty(), 0));
    }
    file.rewind().await.map_err(spool_failed)?;
    let file = file.into_std().await;
    let (file, length) = tokio::task::spawn_blocking(move || decode_file(file, codec, cap))
        .await
        .map_err(|_| decoder_stopped())??;
    let body = Body::from_stream(futures_util::stream::try_unfold(
        tokio::fs::File::from_std(file),
        |mut file| async move {
            let mut piece = vec![0; MIN_ENCODED_BYTES];
            let read = file.read(&mut piece).await?;
            if read == 0 {
                return Ok::<_, io::Error>(None);
            }
            piece.truncate(read);
            Ok(Some((Bytes::from(piece), file)))
        },
    ));
    Ok((body, length))
}

fn decode_file(file: File, codec: Codec, cap: usize) -> Result<(File, u64), ApiError> {
    let mut decoded = tempfile::tempfile().map_err(spool_failed)?;
    let input = BufReader::with_capacity(MIN_ENCODED_BYTES, file);
    let reader: Box<dyn Read> = match codec {
        Codec::Zstd => Box::new(
            zstd::stream::read::Decoder::with_buffer(input).map_err(|_| invalid_encoding(codec))?,
        ),
        Codec::Gzip => Box::new(flate2::read::MultiGzDecoder::new(input)),
    };
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = reader.take(limit);
    let mut piece = vec![0; MIN_ENCODED_BYTES];
    let mut length = 0u64;
    loop {
        let read = reader
            .read(&mut piece)
            .map_err(|_| invalid_encoding(codec))?;
        if read == 0 {
            break;
        }
        length += read as u64;
        if length > cap as u64 {
            return Err(too_large(cap));
        }
        decoded.write_all(&piece[..read]).map_err(spool_failed)?;
    }
    decoded.rewind().map_err(spool_failed)?;
    Ok((decoded, length))
}

fn invalid_encoding(codec: Codec) -> ApiError {
    ApiError::bad_request(
        format!("the {} request body does not decode", codec.token()),
        None,
    )
}

fn spool_failed(_: io::Error) -> ApiError {
    ApiError::internal_server_error("the request body could not be staged")
}

fn decoder_stopped() -> ApiError {
    ApiError::internal_server_error("the request body decoder stopped")
}
