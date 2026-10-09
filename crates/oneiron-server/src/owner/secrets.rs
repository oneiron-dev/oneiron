//! The owner rotates a secret (ARCH-0069 S6). Rotation is a vault update the
//! owner starts; the next lease materializes the new value, and exhaust built
//! with the old one reads as stale at its next publish or export check.

use axum::body::{Body, Bytes, HttpBody as _};
use base64::Engine as _;
use futures_util::StreamExt as _;
use oneiron::consent::AuthenticatedOwner;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use zeroize::{Zeroize, Zeroizing};

use super::{OwnerError, OwnerResult};

/// The largest rotation body read: a name and one base64 value, far above
/// any key or certificate.
const BODY_LIMIT: usize = 1 << 20;

/// One rotation request. The value travels as standard base64 so binary
/// secrets survive JSON; it reaches the vault's custody plane and no receipt,
/// log or reply.
///
/// Read by [`RotateSecret::read`] rather than an extractor, because every
/// buffer that holds the value or its encoding has to be wiped on every path,
/// a refused request included. Above the transport there are three: the
/// frames the body hands over, the one buffer they are copied into, and the
/// decoded value. Parsing borrows from the second and copies nothing.
pub(crate) struct RotateSecret {
    /// The secret's custody name.
    name: String,
    value: Zeroizing<Vec<u8>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotateFields<'a> {
    name: String,
    /// Raw, so the parser skips the string in place and never unescapes it
    /// into its own scratch buffer, not even when the string fails part way.
    /// Base64 needs no escapes, so a value carrying one is refused.
    #[serde(borrow)]
    value_base64: &'a RawValue,
}

impl RotateSecret {
    pub(crate) async fn read(body: Body) -> OwnerResult<Self> {
        let body = OwnedBody::read(body).await?;
        let fields: RotateFields<'_> =
            serde_json::from_slice(&body.0).map_err(|_| invalid_body())?;
        let not_base64 = || OwnerError::Invalid("value_base64 must be standard base64".into());
        let encoded = fields
            .value_base64
            .get()
            .as_bytes()
            .strip_prefix(b"\"")
            .and_then(|raw| raw.strip_suffix(b"\""))
            .ok_or_else(not_base64)?;
        // Sized up front so decoding never reallocates and leaves a copy behind;
        // a decode that fails part way is wiped with the rest.
        let mut value = Zeroizing::new(Vec::with_capacity(base64::decoded_len_estimate(
            encoded.len(),
        )));
        base64::engine::general_purpose::STANDARD
            .decode_vec(encoded, &mut value)
            .map_err(|_| not_base64())?;
        if value.is_empty() {
            return Err(OwnerError::Invalid("a rotated secret needs a value".into()));
        }
        Ok(Self {
            name: fields.name,
            value,
        })
    }
}

impl std::fmt::Debug for RotateSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotateSecret")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// The body in the one buffer this request owns, wiped when it drops. It is
/// sized before the first byte arrives and never grows: growing would move
/// the bytes and free the old allocation unwiped.
struct OwnedBody(Vec<u8>);

impl OwnedBody {
    async fn read(body: Body) -> OwnerResult<Self> {
        let room = match body.size_hint().upper() {
            None => BODY_LIMIT,
            Some(declared) => usize::try_from(declared)
                .ok()
                .filter(|declared| *declared <= BODY_LIMIT)
                .ok_or_else(invalid_body)?,
        };
        let mut owned = Self(Vec::with_capacity(room));
        let mut frames = body.into_data_stream();
        while let Some(frame) = frames.next().await {
            let frame = frame.map_err(|_| invalid_body())?;
            let fits = frame.len() <= owned.0.capacity() - owned.0.len();
            if fits {
                owned.0.extend_from_slice(&frame);
            }
            wipe_frame(frame);
            if !fits {
                return Err(invalid_body());
            }
        }
        Ok(owned)
    }
}

impl Drop for OwnedBody {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

/// Wipes a frame in place once it is copied, when this request holds its
/// only reference. A frame the server still shares with the connection's read
/// buffer, which hyper splits frames from, is transport memory: no handler
/// reaches it, as none reaches the bearer token read with the headers.
fn wipe_frame(frame: Bytes) {
    if let Ok(mut frame) = frame.try_into_mut() {
        wipe(&mut frame[..]);
    }
}

/// Every buffer the request owns that held the value or its encoding ends
/// here.
fn wipe<B: Zeroize + AsRef<[u8]> + ?Sized>(buffer: &mut B) {
    #[cfg(test)]
    wiped::saw(buffer.as_ref());
    buffer.zeroize();
}

fn invalid_body() -> OwnerError {
    OwnerError::Invalid("invalid JSON request body".into())
}

/// The wipe hook's record, so a test can name a buffer by its contents and
/// see that it went through [`wipe`].
#[cfg(test)]
pub(crate) mod wiped {
    use std::sync::{Mutex, PoisonError};

    static SEEN: Mutex<Vec<blake3::Hash>> = Mutex::new(Vec::new());

    pub(super) fn saw(buffer: &[u8]) {
        SEEN.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(blake3::hash(buffer));
    }

    /// How many wiped buffers held exactly `bytes` just before the wipe.
    pub(crate) fn count(bytes: &[u8]) -> usize {
        let held = blake3::hash(bytes);
        SEEN.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|seen| **seen == held)
            .count()
    }
}

/// What the rotation changed: the generation moved, never the value.
#[derive(Debug, Serialize)]
pub(crate) struct Rotated {
    pub(crate) receipt_id: String,
    pub(crate) name: String,
    pub(crate) from_generation: u32,
    pub(crate) to_generation: u32,
    pub(crate) rotated_at: u64,
}

pub(crate) fn rotate(
    vault: &oneiron::Vault,
    owner: &AuthenticatedOwner,
    request: &RotateSecret,
) -> OwnerResult<Rotated> {
    let receipt = vault.rotate_secret_as_owner(
        owner,
        &request.name,
        &request.value,
        vault.now_recorded_at(),
    )?;
    Ok(Rotated {
        receipt_id: receipt.receipt_id.to_hex(),
        name: receipt.secret_ref,
        from_generation: receipt.from_generation,
        to_generation: receipt.to_generation,
        rotated_at: receipt.rotated_at,
    })
}
