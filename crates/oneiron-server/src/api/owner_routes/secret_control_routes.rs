//! `/v1/owner/secrets/*`: the owner's custody doors over HTTP (OF-422, WILL
//! L04 row 04).
//!
//! Register, rotate and revoke read their bodies after the owner door, as
//! before. A portable secret's change is a custody request on the shared
//! owner-work log: the body may name the holder that does it and the
//! installs he permits to hold its bytes, and every reply carries the
//! request's receipt, why a change stayed on this install, and that delivery
//! to his other machines is unknown. `POST /secrets/rewrap` seals a secret
//! again to the installs he names now. `GET /secrets/custody` is the
//! value-free view a surface reads to ask a change, and `POST
//! /secrets/custody` takes a register or rotate whose protected input the
//! surface sealed to the holder itself, so this install never sees the
//! plaintext; its body spools whole under the disk floor, whatever its
//! length (`sealed_spool`, FIX 5674). Each act's surface is audit only: no
//! route here refuses on where the owner said yes.

pub(crate) mod pending;
mod sealed_spool;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Query, State};
use axum::http::{Extensions, HeaderMap};
use axum::response::Json;
use axum::routing::{get, post};
use base64::Engine as _;
use oneiron::authority::{CustodyChange, CustodyRecipientPermit};
use oneiron::secret_custody::{SealedCustodyChange, SecretCustodyStatus, SecretCustodyView};
use serde::{Deserialize, Serialize};

use super::machine_routes::{act_surface_admitted, parse_revision, revision_hex};
use super::owner_work_routes::OwnerWorkReceiptView;
use super::{OwnerReply, blocking, owner, owner_error};
use crate::api::body_spool::OwnerJsonBody;
use crate::api::{has_json_content_type, query_params};
use crate::auth::CoreAuth;
use crate::error::ApiError;
use crate::owner::{OwnerError, OwnerResult, entity_id, secrets};
use crate::server::SyncServer;

/// `POST /secrets/custody` takes no `DefaultBodyLimit`: its body spools
/// whole under the disk floor (`sealed_spool`), so a frame of numbered
/// envelopes (FIX 5521) is read whatever its length, as the engine carries
/// an input past one row's bound in numbered parts and refuses none for its
/// length (FIX 5445).
pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/secrets/register", post(register_secret))
        .route("/secrets/rotate", post(rotate_secret))
        .route("/secrets/revoke", post(revoke_secret))
        .route("/secrets/rewrap", post(rewrap_secret))
        .route("/secrets/custody", get(custody_view).post(sealed_change))
        .merge(pending::routes())
}

/// The OpenAPI schema of `POST /v1/owner/secrets/rewrap`'s body (FIX 11611): [`RewrapBody`].
pub(crate) fn rewrap_body_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<RewrapBody>()
}

/// The OpenAPI schema of `POST /v1/owner/secrets/rewrap`'s answer (FIX 11611):
/// [`secrets::CustodyReply`].
pub(crate) fn custody_reply_schema() -> serde_json::Value {
    oneiron_contracts::code_run::vault_read::request_schema::<secrets::CustodyReply>()
}

/// The body is read by `RegisterSecret::read`, as rotation's is: the owner
/// door runs first, so a refused caller's body is never read.
async fn register_secret(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    extensions: Extensions,
    body: Body,
) -> OwnerReply<secrets::Registered> {
    let owner = owner(&auth, &server)?;
    if !has_json_content_type(&headers) {
        return Err(ApiError::bad_request("invalid JSON request body", None).into());
    }
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = secrets::RegisterSecret::read(body)
        .await
        .map_err(owner_error)?;
    let registered =
        blocking(move || secrets::register(server.vault(), &owner, surface, &request)).await?;
    Ok(Json(registered))
}

/// The body is read by `RotateSecret::read`, not `Json`: the extractor's
/// body copy and parser scratch would outlive the request unwiped.
async fn rotate_secret(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    extensions: Extensions,
    body: Body,
) -> OwnerReply<secrets::CustodyRotated> {
    let owner = owner(&auth, &server)?;
    if !has_json_content_type(&headers) {
        return Err(ApiError::bad_request("invalid JSON request body", None).into());
    }
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = secrets::RotateSecret::read(body)
        .await
        .map_err(owner_error)?;
    let rotated =
        blocking(move || secrets::rotate(server.vault(), &owner, surface, &request)).await?;
    Ok(Json(rotated))
}

/// `POST /v1/owner/secrets/revoke` with `{"name"}`: the record goes terminal
/// and every lease over it is revoked (OF-422), and a portable one's revoke
/// is carried to the owner's other machines from this request's surface.
/// The body is read by `secrets::read_revoke`, after the owner door, as
/// rotation's is.
async fn revoke_secret(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    extensions: Extensions,
    body: Body,
) -> OwnerReply<secrets::CustodyRotated> {
    let owner = owner(&auth, &server)?;
    if !has_json_content_type(&headers) {
        return Err(ApiError::bad_request("invalid JSON request body", None).into());
    }
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let name = secrets::read_revoke(body).await.map_err(owner_error)?;
    let revoked = blocking(move || secrets::revoke(server.vault(), &owner, surface, &name)).await?;
    Ok(Json(revoked))
}

/// `POST /v1/owner/secrets/rewrap`: the installs the owner permits now.
#[derive(Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
struct RewrapBody {
    name: String,
    /// The install that holds the secret, as 32 hex; this install when
    /// absent.
    #[serde(default)]
    holder: Option<String>,
    /// The installs permitted to hold it, as 32 hex each.
    recipients: Vec<String>,
}

/// `POST /v1/owner/secrets/rewrap`: seals a portable secret again, same
/// generation and status, to the installs the body names, by its holder.
async fn rewrap_secret(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    extensions: Extensions,
    payload: OwnerJsonBody<RewrapBody>,
) -> OwnerReply<secrets::CustodyReply> {
    let owner = owner(&auth, &server)?;
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let request = payload.read(&server).await?;
    let reply = blocking(move || {
        let plan = secrets::custody_plan(request.holder, request.recipients)?;
        secrets::rewrap(server.vault(), &owner, surface, &request.name, &plan)
    })
    .await?;
    Ok(Json(reply))
}

#[derive(Deserialize)]
struct ViewQuery {
    name: String,
}

/// One install a surface may offer as holder or recipient.
#[derive(Debug, Serialize)]
struct CandidateReply {
    machine: String,
    /// The profile entry a permit binds, as 64 hex.
    profile: String,
    /// The encryption key digest a permit binds, as 64 hex.
    encryption_key_digest: String,
    /// The key a surface seals an input to: its suite and public bytes.
    suite: u16,
    encryption_key_base64: String,
    this_install: bool,
}

/// What a surface reads to ask a custody change, value-free.
#[derive(Debug, Serialize)]
struct ViewReply {
    vault_id: String,
    secret_id: String,
    name: String,
    known: bool,
    held_here: bool,
    portable: bool,
    status: Option<&'static str>,
    generation: u32,
    seen: String,
    live: Vec<OwnerWorkReceiptView>,
    candidates: Vec<CandidateReply>,
    delivery: &'static str,
}

impl From<SecretCustodyView> for ViewReply {
    fn from(view: SecretCustodyView) -> Self {
        Self {
            vault_id: revision_hex(&view.vault_id),
            secret_id: view.secret_id.to_hex(),
            name: view.name,
            known: view.known,
            held_here: view.held_here,
            portable: view.portable,
            status: view.status.map(SecretCustodyStatus::as_str),
            generation: view.generation,
            seen: revision_hex(&view.seen),
            live: view
                .live
                .into_iter()
                .map(OwnerWorkReceiptView::from)
                .collect(),
            candidates: view
                .candidates
                .into_iter()
                .map(|candidate| CandidateReply {
                    machine: candidate.permit.machine.to_hex(),
                    profile: revision_hex(&candidate.permit.profile),
                    encryption_key_digest: revision_hex(&candidate.permit.encryption_key),
                    suite: candidate.suite,
                    encryption_key_base64: base64::engine::general_purpose::STANDARD
                        .encode(&candidate.encryption_key),
                    this_install: candidate.this_install,
                })
                .collect(),
            delivery: view.delivery.as_str(),
        }
    }
}

/// `GET /v1/owner/secrets/custody?name=NAME`: the secret's id, generation
/// and custody revision, its live requests, and the live linked installs a
/// surface may offer. Offering one is not the owner's consent.
async fn custody_view(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    query: Result<Query<ViewQuery>, QueryRejection>,
) -> OwnerReply<ViewReply> {
    let owner = owner(&auth, &server)?;
    let query = query_params(query)?;
    let view = blocking(move || -> OwnerResult<ViewReply> {
        Ok(server
            .vault()
            .secret_custody_view(&owner, &query.name)?
            .into())
    })
    .await?;
    Ok(Json(view))
}

/// One exact permit a sealed input binds.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PermitBody {
    machine: String,
    profile: String,
    encryption_key_digest: String,
}

/// A register or rotate whose protected input the surface sealed itself:
/// every member but `input_base64`, which `sealed_spool` decodes into a
/// file of its own as it reads the body. That member is the input sealed to
/// the holder's key, as standard base64: one envelope, or the frame of
/// numbered envelopes, two or more, which a body past one envelope's
/// plaintext bound needs (FIX 5521): its label, the envelope count as a
/// big-endian `u32`, each envelope's length as a big-endian `u32` and its
/// bytes in order, then the closing mark. Each numbered envelope seals the
/// input label and the next run of the body under the one-envelope key id,
/// then its index and the count, each a big-endian `u32`
/// (`secret_custody::control::input::envelopes`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedHead {
    /// `register` or `rotate`.
    change: String,
    secret_id: String,
    generation: u32,
    /// The custody revision the surface read, as 64 hex.
    seen: String,
    holder: String,
    recipients: Vec<PermitBody>,
    /// For a register, the `manifest_ref` its sealed record names: this
    /// install attaches the manifest it resolves for it. Absent, it attaches
    /// the vault's one current approved manifest, or records that the
    /// register carries none and the reply says so.
    #[serde(default)]
    manifest_ref: Option<String>,
}

/// `POST /v1/owner/secrets/custody`: records a register or rotate whose
/// protected input the surface sealed to the holder under the binding `GET
/// /secrets/custody` gave it. This install sees only ciphertext. The body is
/// read after the owner door, spooled whole under the disk floor, whose
/// `disk_capacity` is the only refusal its size meets (FIX 5674), and its
/// input decoded into a file of its own (FIX 7917); the floor keeps the room
/// the engine stores the input in until the change returns. The custody
/// door takes the input as one slice, so it is read from that file once,
/// here (FIX 11140: L04's reader path through persistence and execution).
async fn sealed_change(
    auth: CoreAuth,
    State(server): State<Arc<SyncServer>>,
    headers: HeaderMap,
    extensions: Extensions,
    body: Body,
) -> OwnerReply<secrets::CustodyReply> {
    let owner = owner(&auth, &server)?;
    if !has_json_content_type(&headers) {
        return Err(ApiError::bad_request("invalid JSON request body", None).into());
    }
    let surface = act_surface_admitted(&server, &auth, &headers, &extensions);
    let sealed = sealed_spool::read::<SealedHead>(&server, &headers, body).await?;
    let reply = blocking(move || -> OwnerResult<secrets::CustodyReply> {
        // The whole request moves here, its floor claim with it, so the room
        // stays held while the custody work runs, even past a cancel.
        let sealed = sealed;
        let request = &sealed.head;
        let change = CustodyChange::from_name(&request.change)
            .filter(|change| matches!(change, CustodyChange::Register | CustodyChange::Rotate))
            .ok_or_else(|| OwnerError::Invalid("change must be register or rotate".into()))?;
        let recipients = request
            .recipients
            .iter()
            .map(|permit| {
                Ok(CustodyRecipientPermit {
                    machine: entity_id("recipients.machine", &permit.machine)?,
                    profile: parse_revision("recipients.profile", &permit.profile)?,
                    encryption_key: parse_revision(
                        "recipients.encryption_key_digest",
                        &permit.encryption_key_digest,
                    )?,
                })
            })
            .collect::<OwnerResult<Vec<_>>>()?;
        let input = sealed
            .input
            .ok_or_else(|| OwnerError::Invalid("input_base64 must be standard base64".into()))?
            .read_all()
            .map_err(|error| OwnerError::Host(error.into()))?;
        let vault = server.vault();
        let custody = vault.seal_custody_change_as_owner(
            &owner,
            surface,
            &SealedCustodyChange {
                manifest_ref: request.manifest_ref.as_deref(),
                change,
                secret_id: entity_id("secret_id", &request.secret_id)?,
                generation: request.generation,
                seen: parse_revision("seen", &request.seen)?,
                holder: entity_id("holder", &request.holder)?,
                recipients: &recipients,
                input: &input,
            },
            vault.now_recorded_at(),
        )?;
        Ok(custody.into())
    })
    .await?;
    Ok(Json(reply))
}
