//! Every `/v1/owner` JSON route's body (FIX 8195, Rule 5). The extractor
//! reads nothing: the route runs its own door first, then reads the body. A
//! body whose declared length fits [`IN_MEMORY_BODY_BYTES`] is read in memory
//! as before; any other spools whole on the vault's disk and decodes from
//! there, so no length is refused as invalid JSON and none is held in memory
//! twice (CALLS OWNER_JSON_IN_MEMORY_BYTES).

use std::convert::Infallible;
use std::marker::PhantomData;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRequest, Request};
use serde::de::DeserializeOwned;

use super::{declared_length, invalid_json, spool_then};
use crate::api::has_json_content_type;
use crate::error::ApiError;
use crate::server::SyncServer;

/// The largest declared body read in memory; a longer one, or one of no
/// declared length, is spooled. The extractor ceiling these routes had, kept
/// as the line between the two reads, never as a refusal.
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
            json: has_json_content_type(&parts.headers),
            declared: declared_length(&parts.headers),
            body,
            decoded: PhantomData,
        })
    }
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
        if !self.json {
            return Err(invalid_json());
        }
        if let Some(size) = self.declared
            && size <= IN_MEMORY_BODY_BYTES as u64
        {
            let bytes = axum::body::to_bytes(self.body, IN_MEMORY_BODY_BYTES)
                .await
                .map_err(|_| invalid_json())?;
            return serde_json::from_slice(&bytes).map_err(|_| invalid_json());
        }
        spool_then(server, self.declared, self.body, None, |mut spool| {
            spool.json::<T>()
        })
        .await
        .map_err(super::Unspooled::refusal)?
        .ok_or_else(invalid_json)
    }
}
