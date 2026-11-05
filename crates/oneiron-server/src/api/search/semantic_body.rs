//! Whole semantic request bytes, admitted before the raw buffer is allocated.
//! The decoded query and the transport's small spool buffers are separate owners.

use std::io::Read;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::Json;
use axum::body::Body;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::{HeaderMap, header};
use serde::de::IgnoredAny;

use super::SemanticSearchRequest;
use crate::api::body_spool::{SpoolPolicy, Unspooled, declared_length, spool_then};
use crate::error::ApiError;
use crate::server::SyncServer;

struct CancelOnDrop(Arc<AtomicBool>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Called after the semantic route has admitted the caller. No row ceiling
/// truncates the body, and no request retains a partial raw buffer while
/// waiting for the rest of its memory. The complete spool names the one
/// allocation, not an untrusted Content-Length.
pub(super) async fn read(
    server: &SyncServer,
    headers: &HeaderMap,
    body: Body,
) -> Result<SemanticSearchRequest, ApiError> {
    let mut probe = Request::new(Body::empty());
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        probe
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type.clone());
    }
    if let Err(rejection @ JsonRejection::MissingJsonContentType(_)) =
        Json::<IgnoredAny>::from_request(probe, &()).await
    {
        return Err(invalid(rejection));
    }

    let stopped = Arc::new(AtomicBool::new(false));
    let _cancel = CancelOnDrop(Arc::clone(&stopped));
    let memory = server.memory.clone();
    spool_then(
        server,
        declared_length(headers),
        body,
        SpoolPolicy::default(),
        move |mut spool| {
            let mut reader = spool.reader();
            let bytes = reader.get_ref().metadata().map_err(|_| unread())?.len();
            let length = usize::try_from(bytes).map_err(|_| unread())?;
            let mut lease = if bytes == 0 {
                memory.empty_lease()
            } else {
                memory
                    .lease_untimed(bytes, &|| stopped.load(Ordering::Relaxed))
                    .map_err(|_| unread())?
            };
            if stopped.load(Ordering::Relaxed) {
                return Err(unread());
            }
            let mut raw = Vec::<u8>::new();
            raw.try_reserve_exact(length).map_err(|_| unread())?;
            raw.resize(length, 0);
            lease.materialized(bytes, raw.capacity() as u64);
            reader.read_exact(&mut raw).map_err(|_| unread())?;
            let parsed = Json::<SemanticSearchRequest>::from_bytes(&raw)
                .map(|Json(params)| params)
                .map_err(invalid);
            drop(raw);
            drop(lease);
            parsed
        },
    )
    .await
    .map_err(|ending| match ending {
        Unspooled::NoRoom => unread(),
        Unspooled::Failed => ApiError::bad_request(
            "invalid semantic search body: the request body did not arrive whole",
            None,
        ),
    })?
}

fn invalid(rejection: JsonRejection) -> ApiError {
    ApiError::bad_request(format!("invalid semantic search body: {rejection}"), None)
}

fn unread() -> ApiError {
    ApiError::internal_server_error("semantic search body read failed")
}
