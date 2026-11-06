//! Ordinary compressed facade requests, staged before the route reads them.

use std::fs::File;
use std::io::{BufReader, Read, Seek, Write};

use axum::body::Body;
use axum::extract::Request;

use super::{Codec, MIN_ENCODED_BYTES, too_large};
use crate::api::body_stage::{self, StageError};
use crate::error::ApiError;

/// Ephemeral and custody calls keep the codec's existing in-memory path.
/// A held room NOTE's editor close need not carry its session header.
pub(super) fn stages(request: &Request) -> bool {
    let Some(verb) = request.uri().path().strip_prefix("/v1/core/facade/") else {
        return false;
    };
    body_stage::facade_staged(verb, request.headers())
}

/// Both encoded and decoded lengths meet the same ceiling as the RAM path.
/// Decoding finishes before dispatch, so a malformed stream is still a codec
/// refusal, not a partial request reaching the receipt or the JSON reader.
pub(super) async fn decode_body(
    body: Body,
    codec: Codec,
    cap: usize,
) -> Result<(Body, u64), ApiError> {
    let (file, length) = body_stage::stage(body, cap)
        .await
        .map_err(|error| match error {
            StageError::Input | StageError::TooLarge => too_large(cap),
            StageError::Io => body_stage::staging_failed(),
            StageError::Stopped => body_stage::worker_stopped(),
        })?;
    if length == 0 {
        return Ok((Body::empty(), 0));
    }
    let (file, length) = tokio::task::spawn_blocking(move || decode_file(file, codec, cap))
        .await
        .map_err(|_| body_stage::worker_stopped())??;
    Ok((body_stage::replay(file), length))
}

fn decode_file(file: File, codec: Codec, cap: usize) -> Result<(File, u64), ApiError> {
    let mut decoded = tempfile::tempfile().map_err(|_| body_stage::staging_failed())?;
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
        decoded
            .write_all(&piece[..read])
            .map_err(|_| body_stage::staging_failed())?;
    }
    decoded.rewind().map_err(|_| body_stage::staging_failed())?;
    Ok((decoded, length))
}

fn invalid_encoding(codec: Codec) -> ApiError {
    ApiError::bad_request(
        format!("the {} request body does not decode", codec.token()),
        None,
    )
}
