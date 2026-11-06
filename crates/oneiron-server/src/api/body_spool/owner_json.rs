//! Every `/v1/owner` JSON route's body (FIX 8195, Rule 5). The extractor
//! reads nothing: the route runs its own door first, then reads the body. A
//! body that fits [`IN_MEMORY_BODY_BYTES`] is read in memory as before,
//! whether it declared its length or not; a longer one spools whole on the
//! vault's disk and decodes from there, so no length is refused as invalid
//! JSON and none is held in memory twice (CALLS OWNER_JSON_IN_MEMORY_BYTES).
//! The default read sets no wait of its own on the client: the listener's
//! body policy is the only one, as for a body read in memory. Transfer reads
//! opt into the existing disk reserve and idle policy for their spool.

use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::header;
use futures_util::{StreamExt, stream};
use serde::de::{DeserializeOwned, IgnoredAny};

use super::{BodySpool, SpoolPolicy, Unspooled, declared_length, invalid_json, spool_then};
use crate::error::ApiError;
use crate::server::SyncServer;

/// The largest body read in memory; a longer one is spooled. The extractor
/// ceiling these routes had, kept as the line between the two reads, never
/// as a refusal.
const IN_MEMORY_BODY_BYTES: usize = 2 * 1024 * 1024;

/// An owner route's JSON body as `T`, unread until the route's own door has
/// admitted its caller and calls [`Self::read`].
pub(in crate::api) struct OwnerJsonBody<T> {
    json: bool,
    declared: Option<u64>,
    body: Body,
    decoded: PhantomData<fn() -> T>,
}

impl<T> FromRequest<Arc<SyncServer>> for OwnerJsonBody<T> {
    type Rejection = Infallible;

    async fn from_request(
        request: Request,
        _server: &Arc<SyncServer>,
    ) -> Result<Self, Self::Rejection> {
        let (parts, body) = request.into_parts();
        Ok(Self {
            json: json_content_type(parts.headers.get(header::CONTENT_TYPE)).await,
            declared: declared_length(&parts.headers),
            body,
            decoded: PhantomData,
        })
    }
}

/// Whether the request names JSON exactly as Axum's `Json` judges it: a
/// parsed `application/json` or `application/*+json`. Axum's own extractor
/// is asked, over the header alone, so the two never drift.
async fn json_content_type(content_type: Option<&header::HeaderValue>) -> bool {
    let mut probe = Request::new(Body::empty());
    if let Some(content_type) = content_type {
        probe
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type.clone());
    }
    !matches!(
        axum::Json::<IgnoredAny>::from_request(probe, &()).await,
        Err(JsonRejection::MissingJsonContentType(_))
    )
}

/// A body read in memory to its end, or the start of one past
/// [`IN_MEMORY_BODY_BYTES`] and the body still to come.
enum Held {
    Whole(Vec<u8>),
    Past(Body),
}

/// An undeclared body read in memory up to the line, as the extractor read
/// it; one that passes the line is handed on whole, its start first.
async fn hold(body: Body) -> Result<Held, ApiError> {
    let mut frames = body.into_data_stream();
    let mut held = Vec::new();
    while let Some(frame) = frames.next().await {
        held.extend_from_slice(&frame.map_err(|_| invalid_json())?);
        if held.len() > IN_MEMORY_BODY_BYTES {
            let start = stream::iter([Ok::<_, axum::Error>(Bytes::from(held))]);
            return Ok(Held::Past(Body::from_stream(start.chain(frames))));
        }
    }
    Ok(Held::Whole(held))
}

/// A spooled body as JSON `T`, on the spool's worker.
fn decode_spool<T: DeserializeOwned>(
    mut spool: BodySpool,
) -> Result<Option<T>, crate::machine::MemoryRefusal> {
    spool.json()
}

/// A transfer body read for a bulk consumer: whole in memory, or spooled
/// and run through the caller's spool reader on the transfer worker.
pub(in crate::api) enum TransferBody<T, R> {
    Whole(T),
    Bulk(R),
}

/// A body ready to decode: read whole in memory, or still to spool.
enum ReadyBody {
    Memory(Bytes),
    Stream { declared: Option<u64>, body: Body },
}

impl<T: DeserializeOwned + Send + 'static> OwnerJsonBody<T> {
    /// The body as `T`. Call it after the route's door: a body past the
    /// in-memory read is spooled whole before it is decoded.
    ///
    /// # Errors
    /// `invalid JSON request body` when the request is not JSON `T`; a body
    /// that did not arrive whole; capacity when the vault's disk has no room
    /// for its spool.
    pub(in crate::api) async fn read(self, server: &SyncServer) -> Result<T, ApiError> {
        self.read_with_policy(server, SpoolPolicy::default()).await
    }

    /// A transfer body's JSON under the existing disk reserve and idle policy.
    pub(in crate::api) async fn read_for_transfer(
        self,
        server: &SyncServer,
    ) -> Result<T, ApiError> {
        self.read_with_policy(server, SpoolPolicy::custody(server))
            .await
    }

    /// `read_for_transfer` for a caller that reads a spooled body itself:
    /// bodies at or under the in-memory line decode whole as `T`, exactly as
    /// `read_for_transfer` decodes them; longer bodies spool under the same
    /// custody policy and run `spool` over the spool on the transfer worker.
    pub(in crate::api) async fn read_for_transfer_with<R: Send + 'static>(
        self,
        server: &SyncServer,
        spool: impl FnOnce(BodySpool) -> R + Send + 'static,
    ) -> Result<TransferBody<T, R>, ApiError> {
        match self.ready_body().await? {
            ReadyBody::Memory(bytes) => serde_json::from_slice(&bytes)
                .map_err(|_| invalid_json())
                .map(TransferBody::Whole),
            ReadyBody::Stream { declared, body } => {
                spool_then(server, declared, body, SpoolPolicy::custody(server), spool)
                    .await
                    .map_err(Unspooled::refusal)
                    .map(TransferBody::Bulk)
            }
        }
    }

    async fn read_with_policy(
        self,
        server: &SyncServer,
        policy: SpoolPolicy,
    ) -> Result<T, ApiError> {
        match self.ready_body().await? {
            ReadyBody::Memory(bytes) => serde_json::from_slice(&bytes).map_err(|_| invalid_json()),
            ReadyBody::Stream { declared, body } => {
                spool_then(server, declared, body, policy, decode_spool::<T>)
                    .await
                    .map_err(Unspooled::refusal)?
                    .map_err(super::reader_memory_refused)?
                    .ok_or_else(invalid_json)
            }
        }
    }

    /// The in-memory/spool branch shared by whole and bulk reads: the same
    /// declared-length and held-body judgment against the same
    /// [`IN_MEMORY_BODY_BYTES`] line, with the same errors.
    async fn ready_body(self) -> Result<ReadyBody, ApiError> {
        if !self.json {
            return Err(invalid_json());
        }
        match self.declared {
            Some(size) if size <= IN_MEMORY_BODY_BYTES as u64 => {
                let bytes = axum::body::to_bytes(self.body, IN_MEMORY_BODY_BYTES)
                    .await
                    .map_err(|_| invalid_json())?;
                Ok(ReadyBody::Memory(bytes))
            }
            Some(_) => Ok(ReadyBody::Stream {
                declared: self.declared,
                body: self.body,
            }),
            None => match hold(self.body).await? {
                Held::Whole(bytes) => Ok(ReadyBody::Memory(Bytes::from(bytes))),
                Held::Past(body) => Ok(ReadyBody::Stream {
                    declared: self.declared,
                    body,
                }),
            },
        }
    }
}
