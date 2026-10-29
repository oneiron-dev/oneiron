//! `POST /v1/owner/secrets/anchor-sign` (FIX 1956): the owner's recovery
//! kit pushes a portable secret's current custody transition, signed with
//! his owner anchor, to the installs he names, from a running server, as
//! `oneiron secrets anchor-sign` does on a stopped vault (CALLS
//! CUSTODY_KIT_PUSH). The kit is this one call's proof: its pieces rebuild
//! the seed for this call alone, and the engine still takes the push only
//! from an install with no live machine profile, against the root this
//! vault pins. Nothing of the kit is stored, logged or receipted, and no
//! seed is kept as a convenience credential.
//!
//! What is wiped: the body is read in memory, never spooled to disk, into
//! one buffer sized up front and wiped on drop ([`ANCHOR_SIGN_BODY_BYTES`]);
//! the decoded recovery codes and passphrase are wiped when the request
//! drops, on every return, early ones included; the kit and the seed it
//! rebuilds wipe themselves. Not wiped: the transport's own buffers before
//! this route reads the body, and the JSON parser's scratch for a string
//! that carries escapes.
//!
//! The kit's recipient rule holds as for the other target calls: a hosted
//! or managed install takes no kit ([`OwnerDevice`]), and the call names
//! its `target`, refused as `kit_target_elsewhere` when this install holds
//! another machine id. The machine proof is not asked: an install with no
//! live profile, the only one the engine lets push, cannot prove itself.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::response::Json;
use axum::routing::post;
use futures_util::StreamExt;
use oneiron::EntityId;
use serde::Deserialize;
use zeroize::{Zeroize, Zeroizing};

use super::super::{OwnerReply, blocking, owner, owner_error};
use super::{KIT_TARGET_ELSEWHERE, Kit, OwnerDevice, kit_target_refused};
use crate::api::has_json_content_type;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::owner::secrets::{self, AnchorSigned};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

/// The most of an anchor-sign body read: a codec bound far past any push
/// (a kit's pieces and passphrase, a name and at most 64 recipients take a
/// few KiB), held in memory in one wiped buffer and never spooled.
const ANCHOR_SIGN_BODY_BYTES: usize = 64 * 1024;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/secrets/anchor-sign", post(anchor_sign))
}

/// One kit push. No `Debug`: it carries the kit, wiped on drop.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorSign {
    /// The install this call's kit is for, 32 hex: this one.
    target: String,
    /// The portable secret's custody name.
    name: String,
    /// The installs its value is sealed to, 32 hex each.
    recipients: Vec<String>,
    /// The kit's pieces, as recovery codes.
    pieces: Vec<String>,
    #[serde(default)]
    passphrase: Option<String>,
}

impl Drop for AnchorSign {
    fn drop(&mut self) {
        self.pieces.zeroize();
        self.passphrase.zeroize();
    }
}

/// The body as [`AnchorSign`], read in memory into one buffer sized up
/// front, so no copy of it is left behind as it grows, and wiped on drop.
async fn read_body(headers: &HeaderMap, body: Body) -> Result<AnchorSign, ApiError> {
    let invalid = || ApiError::bad_request("invalid JSON request body", None);
    if !has_json_content_type(headers) {
        return Err(invalid());
    }
    let mut held = Zeroizing::new(Vec::with_capacity(ANCHOR_SIGN_BODY_BYTES));
    let mut frames = body.into_data_stream();
    while let Some(frame) = frames.next().await {
        let frame = frame.map_err(|_| invalid())?;
        let received = held.len() + frame.len();
        if received > ANCHOR_SIGN_BODY_BYTES {
            return Err(ApiError::payload_too_large("body", ANCHOR_SIGN_BODY_BYTES, received));
        }
        held.extend_from_slice(&frame);
    }
    serde_json::from_slice(&held).map_err(|_| invalid())
}

/// The push's target: `named` must be this install's own machine id when it
/// holds one. Refused before any kit is parsed.
fn anchor_target(server: &SyncServer, named: &str) -> Result<(), ApiError> {
    let named = EntityId::from_hex(named)
        .map_err(|_| ApiError::bad_request("target must be a 32-hex machine id", Some("target")))?;
    let local = server
        .vault()
        .local_machine()
        .map_err(|error| owner_error(OwnerError::from(error)))?;
    match local {
        Some(machine) if machine.id != named => Err(kit_target_refused(
            KIT_TARGET_ELSEWHERE,
            "the kit names another install as its target; this install takes no kit for it",
            "Send the kit to the named install's own call.",
        )),
        _ => Ok(()),
    }
}

/// `POST /v1/owner/secrets/anchor-sign` with `{"target", "name",
/// "recipients", "pieces", "passphrase"?}`: the owner's kit rebuilds his
/// recovery root's seed for this vault, and the engine pushes the secret's
/// current transition, anchor-signed, to the recipients. The answer says
/// whether a transition was written.
async fn anchor_sign(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    _: OwnerDevice,
    headers: HeaderMap,
    body: Body,
) -> OwnerReply<AnchorSigned> {
    let owner = owner(&auth, &server)?;
    let mut request = read_body(&headers, body).await?;
    anchor_target(&server, &request.target)?;
    let vault = Arc::clone(&server.vault);
    let signed = blocking(move || -> OwnerResult<AnchorSigned> {
        let recipients = std::mem::take(&mut request.recipients);
        let recipients = secrets::custody_plan(None, recipients)?.recipients;
        let kit = Kit::parse(std::mem::take(&mut request.pieces), request.passphrase.take())?;
        let seed = kit.seed(&vault)?;
        secrets::sign_with_anchor(&vault, &owner, &seed, &request.name, &recipients)
    })
    .await?;
    Ok(Json(signed))
}
