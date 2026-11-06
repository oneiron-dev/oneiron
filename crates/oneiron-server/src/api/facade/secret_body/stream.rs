//! Ordinary recorded facade input, parsed from staged bytes without a Value cache.

use std::fs::File;
use std::io::{BufReader, Read, Seek};

use axum::body::Body;
use oneiron::memory::caps::MAX_REMOTE_REQUEST_BYTES;
use oneiron::sync::transport::CODEC_MIN_FRAME_BYTES;
use serde_json::Value;

use crate::api::body_stage::{self, StageError};
use crate::error::ApiError;

pub(in crate::api::facade) async fn read(body: Body) -> Result<(Body, Option<Value>, String), ApiError> {
    let (file, length) = match body_stage::stage(body, MAX_REMOTE_REQUEST_BYTES).await {
        Ok(staged) => staged,
        Err(StageError::Input | StageError::TooLarge) => return Ok(empty()),
        Err(StageError::Io) => return Err(body_stage::staging_failed()),
        Err(StageError::Stopped) => return Err(body_stage::worker_stopped()),
    };
    if length == 0 {
        return Ok(empty());
    }
    let (file, value, digest) = tokio::task::spawn_blocking(move || parse(file))
        .await
        .map_err(|_| body_stage::worker_stopped())??;
    Ok((body_stage::replay(file), value, digest))
}

fn empty() -> (Body, Option<Value>, String) {
    (
        Body::empty(),
        None,
        oneiron::receipt::call_bytes_digest(b""),
    )
}

fn parse(mut file: File) -> Result<(File, Option<Value>, String), ApiError> {
    let parsed = {
        let reader = BufReader::with_capacity(CODEC_MIN_FRAME_BYTES, &mut file);
        serde_json::from_reader(reader)
    };
    let value = match parsed {
        Ok(value) => Some(value),
        Err(error) if error.is_io() => return Err(body_stage::staging_failed()),
        Err(_) => None,
    };
    let digest = match &value {
        Some(value) => oneiron::receipt::call_json_digest(value),
        None => {
            file.rewind().map_err(|_| body_stage::staging_failed())?;
            let mut hasher = blake3::Hasher::new();
            let mut piece = vec![0; CODEC_MIN_FRAME_BYTES];
            loop {
                let read = file
                    .read(&mut piece)
                    .map_err(|_| body_stage::staging_failed())?;
                if read == 0 {
                    break;
                }
                hasher.update(&piece[..read]);
            }
            hasher.finalize().to_hex().to_string()
        }
    };
    file.rewind().map_err(|_| body_stage::staging_failed())?;
    Ok((file, value, digest))
}
