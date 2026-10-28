//! `POST /v1/owner/secrets/anchor-sign` (FIX 1956): the owner's recovery
//! kit pushes a portable secret's current custody transition, signed with
//! his owner anchor, to the installs he names, from a running server, as
//! `oneiron secrets anchor-sign` does on a stopped vault (CALLS
//! CUSTODY_KIT_PUSH). The kit is this one call's proof: its pieces rebuild
//! the seed for this call alone, every buffer is wiped on drop, and nothing
//! is stored, logged or receipted. No seed is kept as a convenience
//! credential, and the engine still takes the push only from an install
//! with no live machine profile, against the root this vault pins.
//!
//! The kit's recipient rule holds as for the other target calls: a hosted
//! or managed install takes no kit ([`OwnerDevice`]), and the call names
//! its `target`, refused as `kit_target_elsewhere` when this install holds
//! another machine id. The machine proof is not asked: an install with no
//! live profile, the only one the engine lets push, cannot prove itself.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::response::Json;
use axum::routing::post;
use oneiron::EntityId;
use serde::Deserialize;

use super::super::{OwnerReply, blocking, owner, owner_error};
use super::{KIT_TARGET_ELSEWHERE, Kit, OwnerDevice, kit_target_refused};
use crate::api::body_spool::OwnerJsonBody;
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::owner::secrets::{self, AnchorSigned};
use crate::owner::{OwnerError, OwnerResult};
use crate::server::SyncServer;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new().route("/secrets/anchor-sign", post(anchor_sign))
}

/// One kit push. No `Debug`: it carries the kit.
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
    payload: OwnerJsonBody<AnchorSign>,
) -> OwnerReply<AnchorSigned> {
    let owner = owner(&auth, &server)?;
    let body = payload.read(&server).await?;
    anchor_target(&server, &body.target)?;
    let vault = Arc::clone(&server.vault);
    let signed = blocking(move || -> OwnerResult<AnchorSigned> {
        let recipients = secrets::custody_plan(None, body.recipients)?.recipients;
        let kit = Kit::parse(body.pieces, body.passphrase)?;
        let seed = kit.seed(&vault)?;
        secrets::sign_with_anchor(&vault, &owner, &seed, &body.name, &recipients)
    })
    .await?;
    Ok(Json(signed))
}
