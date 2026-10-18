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
    KIT_BUNDLE_FETCH_PATH, KitBundleFetch, SealedBundleObject, kit_bundle_fetch_origin,
    kit_sealed_bundle_part, sealed_digest_hex, sealed_generation_from_hex, sealed_generation_hex,
};
use oneiron::world_keys::RecoveryRootId;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{parse_signature, parse_slip_id};
use crate::error::{ApiError, ApiErrorEnvelope, EnvelopedApiError};
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
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KitBundlePartRequest {
    /// The vault, 64 hex.
    vault_id: String,
    /// The kit's recovery root, 64 hex.
    root: String,
    /// The generation, 48 hex; absent or null for the newest kept for the root.
    #[serde(default)]
    generation: Option<String>,
    /// The object: `bundle` or `pads`.
    object: String,
    /// The byte offset the slice starts at.
    offset: u64,
    /// When the kit signed the request, in Unix seconds. The home takes it
    /// within 300 seconds of its own clock.
    timestamp: u64,
    /// 32 fresh random bytes, 64 hex. The home takes each nonce once.
    nonce: String,
    /// The root's owner anchor's Ed25519 signature over the request, 128 hex.
    signature: String,
}

/// One slice of a kept object, with the object's whole length and digest.
#[derive(Serialize, ToSchema)]
pub(super) struct KitBundlePartResponse {
    /// The generation the slice is from, 48 hex.
    generation: String,
    /// The object: `bundle` or `pads`.
    object: String,
    /// The object's whole length in bytes.
    total: u64,
    /// The object's BLAKE3 digest, 64 hex.
    digest: String,
    /// The byte offset the slice starts at.
    offset: u64,
    /// Whether the slice ends the object.
    last: bool,
    /// The slice, in standard base64; at most 256 KiB once decoded
    /// (`SEALED_BUNDLE_READ_PART_MAX`).
    part: String,
}

/// The address a request names: the URI's authority (HTTP/2), else the Host
/// header, in lower case. A forwarded host is never trusted here.
fn request_origin(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    uri.authority()
        .map(|authority| authority.as_str())
        .or_else(|| headers.get(HOST).and_then(|value| value.to_str().ok()))
        .map(str::to_ascii_lowercase)
}

/// The addresses a kit may have signed for this home, each once (FIX 4298;
/// CALLS: KIT_BUNDLE_ORIGIN_SOURCES, [ConfiguredPublic, RequestAuthority]):
/// the public URL the operator configured (`oauth_resource_indicator`), as
/// the kit reads a home's address, for a home behind a proxy or tunnel that
/// does not keep the kit's Host; then the address the request names.
fn kit_origins(public: Option<&str>, uri: &Uri, headers: &HeaderMap) -> Vec<String> {
    let mut origins: Vec<String> = public
        .and_then(|url| reqwest::Url::parse(url).ok())
        .and_then(|url| kit_bundle_fetch_origin(&url))
        .into_iter()
        .collect();
    if let Some(origin) = request_origin(uri, headers)
        && !origins.contains(&origin)
    {
        origins.push(origin);
    }
    origins
}

/// `POST /v1/recovery/sealed-bundle/part`: one slice of a kept generation's
/// bundle or pad object, with its whole length and digest, as a machine reads
/// it. A request that does not verify, a generation not kept for the root and
/// an offset past the end all look missing.
#[utoipa::path(
    post,
    path = "/v1/recovery/sealed-bundle/part",
    operation_id = "recovery_sealed_bundle_part",
    request_body(
        content = KitBundlePartRequest,
        description = "One signed slice request. No bearer: the signature is the authentication. It is the owner anchor's, of the recovery root a publisher named for the generation, over the vault, the root, the home's address (the host and port of its configured public URL, or the URI authority or Host the request names, port included), the method, this path, the object, the generation, the offset, the time and the nonce.",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "The slice.", body = KitBundlePartResponse, content_type = "application/json"),
        (status = 400, description = "The body does not parse, a field is malformed, or neither the request nor the home's configured public URL names a host.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "The request does not verify, no generation kept for the root matches, or the offset is at or past the object's end. All look the same.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "The sealed bundle read stopped.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(super) async fn part(
    State(server): State<Arc<SyncServer>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<KitBundlePartResponse>, EnvelopedApiError> {
    let input: KitBundlePartRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("the kit fetch does not parse", None))?;
    let bad = |field: &str| ApiError::bad_request("the kit fetch field is malformed", Some(field));
    let mut origins = kit_origins(
        server.config.oauth_resource_indicator.as_deref(),
        &uri,
        &headers,
    )
    .into_iter();
    let generation = input
        .generation
        .as_deref()
        .map(|hex| sealed_generation_from_hex(hex).ok_or_else(|| bad("generation")))
        .transpose()?;
    let fetch = KitBundleFetch {
        vault_id: parse_slip_id(&input.vault_id).map_err(|_| bad("vaultId"))?,
        root: RecoveryRootId(parse_slip_id(&input.root).map_err(|_| bad("root"))?),
        origin: origins
            .next()
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
    let other = origins.next();
    let vault = Arc::clone(server.vault());
    let object = fetch.object;
    let offset = fetch.offset;
    // A request that does not verify for one address takes no nonce, so the
    // other address checks it afresh.
    let read = tokio::task::spawn_blocking(move || {
        let read = kit_sealed_bundle_part(&vault, &fetch, &signature);
        match other {
            Some(origin) if read.is_err() => {
                kit_sealed_bundle_part(&vault, &KitBundleFetch { origin, ..fetch }, &signature)
            }
            _ => read,
        }
    })
    .await
    .map_err(|_| ApiError::internal_server_error("the sealed bundle read stopped"))?;
    let Ok(Some((entry, part))) = read else {
        return Err(ApiError::not_found("sealed bundle", None).into());
    };
    let (total, digest) = entry.object(object);
    Ok(Json(KitBundlePartResponse {
        generation: sealed_generation_hex(&entry.generation),
        object: object.name().to_owned(),
        total,
        digest: sealed_digest_hex(&digest),
        offset,
        last: offset.saturating_add(part.len() as u64) == total,
        part: base64::engine::general_purpose::STANDARD.encode(part),
    }))
}
