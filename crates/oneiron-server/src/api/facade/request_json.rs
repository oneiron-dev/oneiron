//! Facade handler input, read from a staged file for ordinary recorded calls.

use std::fs::File;
use std::io::BufReader;

use axum::extract::{FromRequest, Request};
use axum::http::{HeaderMap, header};
use oneiron::sync::transport::CODEC_MIN_FRAME_BYTES;
use serde_json::Value;

use super::output::{facade_json, invalid_json};
use super::{FACADE_MAX_BODY_BYTES, FacadeApiError};
use crate::api::body_stage::{self, StageError};

pub(super) async fn read<S>(request: Request, state: &S) -> Result<Value, FacadeApiError>
where
    S: Send + Sync,
{
    let verb = request.uri().path().trim_start_matches('/');
    if !body_stage::facade_staged(verb, request.headers()) {
        return facade_json(axum::Json::<Value>::from_request(request, state).await);
    }
    // Use the same MIME parser and accepted types as Axum's JSON extractor,
    // before consuming the body, including application/*+json and parameters.
    if !json_content_type(request.headers()) {
        return Err(invalid_json());
    }
    let (file, _) = match body_stage::stage(request.into_body(), FACADE_MAX_BODY_BYTES).await {
        Ok(staged) => staged,
        Err(StageError::Input | StageError::TooLarge) => return Err(invalid_json()),
        Err(StageError::Io) => return Err(body_stage::staging_failed().into()),
        Err(StageError::Stopped) => return Err(body_stage::worker_stopped().into()),
    };
    tokio::task::spawn_blocking(move || parse(file))
        .await
        .map_err(|_| FacadeApiError::from(body_stage::worker_stopped()))?
}

fn parse(file: File) -> Result<Value, FacadeApiError> {
    serde_json::from_reader(BufReader::with_capacity(CODEC_MIN_FRAME_BYTES, file)).map_err(
        |error| {
            if error.is_io() {
                body_stage::staging_failed().into()
            } else {
                invalid_json()
            }
        },
    )
}

fn json_content_type(headers: &HeaderMap) -> bool {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = content_type.to_str() else {
        return false;
    };
    let Ok(mime) = content_type.parse::<mime::Mime>() else {
        return false;
    };
    mime.type_() == "application"
        && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"))
}
