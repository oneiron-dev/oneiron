//! The kit door to the vault's sealed cloud bundle (FIX 922): an install that
//! holds the recovery kit and no machine of the vault's reads a kept
//! generation's bundle and pad object in slices, to restore from them.
//! Keyless: each request is signed with the owner anchor of the recovery root
//! a publisher named for that generation, and the home serves only ciphertext,
//! only to that root (`oneiron::sync::residence::kit_sealed_bundle_part`).

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::header::HOST;
use axum::http::{HeaderMap, Uri};
use axum::response::Json;
use axum::routing::post;
use base64::Engine;
use oneiron::sync::residence::{
    KIT_BUNDLE_FETCH_PATH, KitBundleFetch, SealedBundleObject, kit_sealed_bundle_part,
    sealed_digest_hex, sealed_generation_from_hex, sealed_generation_hex,
};
use oneiron::world_keys::RecoveryRootId;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::{parse_signature, parse_slip_id};
use crate::error::{ApiError, EnvelopedApiError};
use crate::server::SyncServer;

/// One signed request, with room to spare.
const MAX_BODY_BYTES: usize = 4 * 1024;

pub(super) fn routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route(KIT_BUNDLE_FETCH_PATH, post(part))
        .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
}

/// One slice the kit asks for: the vault, the kit's root, the generation (none
/// for the newest kept for the root), the object and the offset, signed at
/// `timestamp` with a fresh `nonce`; each in lower-case hex.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PartRequest {
    vault_id: String,
    root: String,
    #[serde(default)]
    generation: Option<String>,
    object: String,
    offset: u64,
    timestamp: u64,
    nonce: String,
    signature: String,
}

/// The address a request names: the URI's authority (HTTP/2), else the Host
/// header, in lower case. A forwarded host is never trusted here.
fn request_origin(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    uri.authority()
        .map(|authority| authority.as_str())
        .or_else(|| headers.get(HOST).and_then(|value| value.to_str().ok()))
        .map(str::to_ascii_lowercase)
}

/// `POST /v1/recovery/sealed-bundle/part`: one slice of a kept generation's
/// bundle or pad object, with its whole length and digest, as a machine reads
/// it. A request that does not verify, a generation not kept for the root and
/// an offset past the end all look missing.
async fn part(
    State(server): State<Arc<SyncServer>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, EnvelopedApiError> {
    let input: PartRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("the kit fetch does not parse", None))?;
    let bad = |field: &str| ApiError::bad_request("the kit fetch field is malformed", Some(field));
    let generation = input
        .generation
        .as_deref()
        .map(|hex| sealed_generation_from_hex(hex).ok_or_else(|| bad("generation")))
        .transpose()?;
    let fetch = KitBundleFetch {
        vault_id: parse_slip_id(&input.vault_id).map_err(|_| bad("vaultId"))?,
        root: RecoveryRootId(parse_slip_id(&input.root).map_err(|_| bad("root"))?),
        origin: request_origin(&uri, &headers)
            .ok_or_else(|| ApiError::bad_request("the request names no host", None))?,
        generation,
        object: SealedBundleObject::from_name(&input.object).ok_or_else(|| bad("object"))?,
        offset: input.offset,
        timestamp: input.timestamp,
        nonce: parse_slip_id(&input.nonce).map_err(|_| bad("nonce"))?,
    };
    let signature: [u8; 64] = parse_signature(&input.signature)
        .ok()
        .and_then(|signature| signature.try_into().ok())
        .ok_or_else(|| bad("signature"))?;
    let vault = Arc::clone(server.vault());
    let object = fetch.object;
    let offset = fetch.offset;
    let read =
        tokio::task::spawn_blocking(move || kit_sealed_bundle_part(&vault, &fetch, &signature))
            .await
            .map_err(|_| ApiError::internal_server_error("the sealed bundle read stopped"))?;
    let Ok(Some((entry, part))) = read else {
        return Err(ApiError::not_found("sealed bundle", None).into());
    };
    let (total, digest) = entry.object(object);
    Ok(Json(json!({
        "generation": sealed_generation_hex(&entry.generation),
        "object": object.name(),
        "total": total,
        "digest": sealed_digest_hex(&digest),
        "offset": offset,
        "last": offset.saturating_add(part.len() as u64) == total,
        "part": base64::engine::general_purpose::STANDARD.encode(part),
    })))
}
