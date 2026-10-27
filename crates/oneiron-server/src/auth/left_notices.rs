//! `POST /v1/shared/left-notices` (OF-158 client leave): a device whose
//! person left or was removed from this shared vault learns it, though leave
//! revoked its slips. `POST /v1/shared/removal-export` (OF-150) answers that
//! person, under the same proof, the archive an export-first removal kept
//! for them, and `POST /v1/shared/removal-export/{receipt_id}` the one archive
//! one removal receipt delivered (FIX 1300). Beside those pulls, a removed
//! device holds delivery sessions under the same proof, and the host sends it
//! each archive owed and records its ack ([`delivery`], FIX 3396). The request carries that slip in `x-oneiron-left-slip`
//! (never as a bearer token, which the network door would refuse) and the
//! usual holder proof in `x-oneiron-binding`; the engine checks the slip is
//! one this vault minted and the device holds its key, spends the nonce, and
//! answers only the person's own loss-of-access notices, each signed by this
//! host's root key (FIX 2053). A host holding no signing key answers none.
//! Beside the notices rides the signed ReRoot chain from where the person's
//! env stands to that key, so a device that never folded a re-root still
//! verifies them.
use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::post;
use oneiron::authority::{AuthorityEntryHash, CapabilitySlip, HostSlipIssuer};
use oneiron::federation::{RemovalExportCopy, SignedSharedActOutcome};
use serde::{Deserialize, Serialize};

use super::{BindingProof, parse_signature};
use crate::error::{ApiError, ApiErrorDetails, EnvelopedApiError};
use crate::server::SyncServer;

mod delivery;

/// The header that carries the revoked slip; managed ingress forwards the
/// holder proof beside it (FIX 5452).
pub(super) const LEFT_SLIP_HEADER: &str = "x-oneiron-left-slip";

pub(crate) fn left_notice_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/v1/shared/left-notices", post(left_notices))
        .route("/v1/shared/removal-export", post(removal_exports))
        .route(
            "/v1/shared/removal-export/{receipt_id}",
            post(removal_export),
        )
        .route(
            "/v1/shared/removal-delivery",
            post(delivery::removal_delivery),
        )
        .route(
            "/v1/shared/removal-delivery/ack",
            post(delivery::removal_delivery_ack),
        )
}

/// The person's MemberLeft, MemberRemoved and role-losing Owner notices,
/// and the vault's deletion, each signed by this host's root key.
#[derive(Debug, Serialize)]
struct LeftNotices {
    notices: Vec<SignedSharedActOutcome>,
    /// The signed ReRoot rows, hex, parents first, that hand this host's
    /// root on from where the person's env stands to the key that signed
    /// `notices` (FIX 2053): empty when that env already folded them.
    handoff: Vec<String>,
}

/// Where the person's authority chain stands (FIX 2053): the heads its env
/// folded, hex, so only the handoff past them rides. A request that names
/// none gets the whole chain.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeftNoticesAsk {
    #[serde(default)]
    authority_heads: Vec<String>,
}

/// The heads `ask` names, each 64 hex; a malformed one is a bad request,
/// refused before the nonce is spent.
fn member_heads(
    ask: Option<Json<LeftNoticesAsk>>,
) -> Result<BTreeSet<AuthorityEntryHash>, ApiError> {
    let Some(Json(ask)) = ask else {
        return Ok(BTreeSet::new());
    };
    let parse = |head: &str| -> Option<AuthorityEntryHash> {
        if head.len() != 64 || !head.is_ascii() {
            return None;
        }
        let mut hash = [0; 32];
        for (byte, pair) in hash.iter_mut().zip(head.as_bytes().chunks_exact(2)) {
            *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(hash)
    };
    ask.authority_heads
        .iter()
        .map(|head| {
            parse(head).ok_or_else(|| {
                ApiError::bad_request(
                    "authority_heads must be 64 hex each",
                    Some("authority_heads"),
                )
            })
        })
        .collect()
}

/// The archives export-first removals kept for the person, still within
/// their retention.
#[derive(Debug, Serialize)]
struct RemovalExports {
    exports: Vec<RemovalExportCopy>,
}

/// The revoked slip and the holder proof a removed device presents.
fn left_proof(headers: &HeaderMap) -> Result<(CapabilitySlip, BindingProof, Vec<u8>), ApiError> {
    let slip = headers
        .get(LEFT_SLIP_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|token| CapabilitySlip::from_token(token.trim()).ok())
        .ok_or_else(ApiError::unauthorized)?;
    let proof = BindingProof::from_headers(headers)?;
    let signature = parse_signature(&proof.signature)?;
    Ok((slip, proof, signature))
}

async fn removal_exports(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<RemovalExports>, EnvelopedApiError> {
    let (slip, proof, signature) = left_proof(&headers)?;
    let exports = tokio::task::spawn_blocking(move || {
        server.vault().removed_owner_exports(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
        )
    })
    .await
    .map_err(|_| ApiError::unauthorized())?
    .map_err(|_| ApiError::unauthorized())?;
    Ok(Json(RemovalExports { exports }))
}

/// The archive one removal receipt delivered to the person, while it is
/// within its term.
#[derive(Debug, Serialize)]
struct RemovalExport {
    export: RemovalExportCopy,
}

/// `POST /v1/shared/removal-export/{receipt_id}` (FIX 1300): the archive the
/// removal receipt `receipt_id` delivered to the holder of the left slip,
/// under the same proof as the list. After its term, or for a removal that
/// delivered this person none, it is not found; a malformed id is a bad
/// request, refused before the nonce is spent.
async fn removal_export(
    headers: HeaderMap,
    Path(receipt_id): Path<String>,
    State(server): State<Arc<SyncServer>>,
) -> Result<Json<RemovalExport>, EnvelopedApiError> {
    if oneiron::EntityId::from_hex(&receipt_id).is_err() {
        return Err(ApiError::bad_request("receipt_id must be 32 hex", Some("receipt_id")).into());
    }
    let (slip, proof, signature) = left_proof(&headers)?;
    let export = tokio::task::spawn_blocking(move || {
        server.vault().removed_owner_archive(
            &slip,
            proof.timestamp,
            &signature,
            proof.nonce.as_bytes(),
            &receipt_id,
        )
    })
    .await
    .map_err(|_| ApiError::unauthorized())?
    .map_err(|_| ApiError::unauthorized())?
    .ok_or_else(|| ApiError::not_found("removal_export", None))?;
    Ok(Json(RemovalExport { export }))
}

/// A host with no root key to sign with: it answers no notice, never an
/// unsigned one, and spends no nonce.
fn no_notice_signing_key() -> ApiError {
    ApiError::new(
        "this host holds no signing key for leave notices",
        ApiErrorDetails::NotImplemented,
        ["Every leave notice is signed by the host's root key; this host answers none unsigned."],
    )
}

/// Runs `sign` with this host's root key: the managed issuer, else this
/// install's own self-host root issuer (FIX-LIST 3018). Neither refuses
/// before the engine is asked, so no nonce is spent.
fn with_notice_issuer<T>(
    server: &SyncServer,
    sign: impl FnOnce(&HostSlipIssuer) -> oneiron::Result<T>,
) -> Result<T, ApiError> {
    let issuer = server.host_issuer().ok_or_else(no_notice_signing_key)?;
    sign(issuer).map_err(|_| ApiError::unauthorized())
}

async fn left_notices(
    headers: HeaderMap,
    State(server): State<Arc<SyncServer>>,
    ask: Option<Json<LeftNoticesAsk>>,
) -> Result<Json<LeftNotices>, EnvelopedApiError> {
    let heads = member_heads(ask)?;
    let (slip, proof, signature) = left_proof(&headers)?;
    let (notices, handoff) = tokio::task::spawn_blocking(move || {
        with_notice_issuer(&server, |issuer| {
            server.vault().removed_member_notices_signed(
                issuer,
                &slip,
                proof.timestamp,
                &signature,
                proof.nonce.as_bytes(),
                &heads,
            )
        })
    })
    .await
    .map_err(|_| ApiError::unauthorized())??;
    let handoff = handoff
        .iter()
        .map(|row| row.iter().map(|byte| format!("{byte:02x}")).collect())
        .collect();
    Ok(Json(LeftNotices { notices, handoff }))
}
