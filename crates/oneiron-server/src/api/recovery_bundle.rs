//! The kit door to the vault's sealed cloud bundle (FIX 922): an install that
//! holds the recovery kit and no machine of the vault's reads a kept
//! generation's bundle and pad object in slices, to restore from them.
//! Keyless: each request is signed with the owner anchor of the recovery root
//! a publisher named for that generation, and the home serves only ciphertext,
//! only to that root (`oneiron::sync::residence::kit_sealed_bundle_part`).
//! The kit reads the home's current index of the generations named for its
//! root the same way (`kit_sealed_bundle_index`, FIX 7106), and a kept pad
//! object whose bytes the home lacks answers typed, never as missing.

use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::http::header::HOST;
use axum::http::{HeaderMap, Uri};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::post;
use base64::Engine;
use oneiron::sync::residence::{
    BundlePartRead, KIT_BUNDLE_FETCH_PATH, KIT_PAD_INDEX_FETCH_PATH, KitBundleFetch,
    KitPadIndexFetch, PadObjectUnavailable, SealedBundleEntry, SealedBundleObject,
    kit_bundle_fetch_origin, kit_sealed_bundle_index, kit_sealed_bundle_part, sealed_digest_hex,
    sealed_generation_from_hex, sealed_generation_hex,
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
        .route(KIT_PAD_INDEX_FETCH_PATH, post(index))
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

/// A kept pad object whose bytes the home lacks from the offset asked (FIX
/// 7106), with its generation's entry as the home keeps it now.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct KitPadObjectUnavailableResponse {
    /// Always `PAD_OBJECT_UNAVAILABLE`.
    outcome: String,
    /// The generation, 48 hex.
    generation: String,
    /// Always `pads`.
    object: String,
    /// The pad object's whole length in bytes.
    total: u64,
    /// The pad object's BLAKE3 digest, 64 hex.
    digest: String,
    /// The order the home committed the generation in.
    commit_order: u64,
    /// The byte offset asked for.
    offset: u64,
}

/// The kit's signed read of a page of the home's current index: the vault,
/// the kit's root, the cursor a page before named (none for the first),
/// `timestamp` and a fresh `nonce`; each in lower-case hex.
#[derive(Deserialize, ToSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct KitPadIndexRequest {
    /// The vault, 64 hex.
    vault_id: String,
    /// The kit's recovery root, 64 hex.
    root: String,
    /// The cursor's revision, 64 hex, as a page's `nextCursor` named it;
    /// absent for the first page.
    #[serde(default)]
    retained_revision: Option<String>,
    /// The cursor's commit order: the page holds the generations committed
    /// before it. Absent for the first page.
    #[serde(default)]
    before_commit_order: Option<u64>,
    /// When the kit signed the request, in Unix seconds. The home takes it
    /// within 300 seconds of its own clock.
    timestamp: u64,
    /// 32 fresh random bytes, 64 hex. The home takes each nonce once.
    nonce: String,
    /// The root's owner anchor's Ed25519 signature over the request, 128 hex.
    signature: String,
}

/// One kept generation named for the kit's root.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct KitPadIndexEntry {
    /// The generation, 48 hex.
    generation: String,
    /// The order the home committed it in; the newest is the greatest.
    commit_order: u64,
    /// The bundle's length in bytes.
    bundle_length: u64,
    /// The bundle's BLAKE3 digest, 64 hex.
    bundle_digest: String,
    /// The pad object's length in bytes.
    pads_length: u64,
    /// The pad object's BLAKE3 digest, 64 hex, as the home keeps it now.
    pads_digest: String,
}

/// One page of the generations the home keeps named for the kit's root,
/// newest committed first, the revision of the one read that named them, and
/// where the next page starts when more follow (FIX 9364).
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct KitPadIndexResponse {
    /// The revision of the home's read of its kept generations, 64 hex.
    /// Opaque: it names a read, never an order.
    retained_revision: String,
    generations: Vec<KitPadIndexEntry>,
    /// The cursor to sign for the next page; absent on the last. A request
    /// whose cursor names a revision the home no longer reads gets the first
    /// page of the revision it reads now.
    #[schema(inline)]
    next_cursor: Option<KitPadIndexCursor>,
}

/// Where the next page of the kit's index starts.
#[derive(Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct KitPadIndexCursor {
    /// The revision the page was read at, 64 hex.
    retained_revision: String,
    /// The commit order the page's last generation holds.
    before_commit_order: u64,
}

/// The address a request names: the URI's authority (HTTP/2), else the Host
/// header, in lower case. A forwarded host is never trusted here.
fn request_origin(uri: &Uri, headers: &HeaderMap) -> Option<String> {
    uri.authority()
        .map(|authority| authority.as_str())
        .or_else(|| headers.get(HOST).and_then(|value| value.to_str().ok()))
        .map(str::to_ascii_lowercase)
}

/// The addresses a kit may have signed for this home, each once (FIX 4298,
/// FIX 4404; CALLS: KIT_BUNDLE_ORIGIN_SOURCES, [ConfiguredPublic,
/// RequestAuthority]): each public URL the operator configured, as the kit
/// reads a home's address, for a home behind proxies or tunnels that do not
/// keep the kit's Host; then the address the request names.
fn kit_origins<S: AsRef<str>>(public: &[S], uri: &Uri, headers: &HeaderMap) -> Vec<String> {
    let mut origins = Vec::new();
    let named = public
        .iter()
        .filter_map(|url| reqwest::Url::parse(url.as_ref()).ok())
        .filter_map(|url| kit_bundle_fetch_origin(&url))
        .chain(request_origin(uri, headers));
    for origin in named {
        if !origins.contains(&origin) {
            origins.push(origin);
        }
    }
    origins
}

/// The public URLs the operator configured for kit fetches (CALLS:
/// KIT_BUNDLE_PUBLIC_URLS, `kit_bundle_public_urls`): that list, or, when it
/// is empty, the one `oauth_resource_indicator`.
fn kit_public_urls(server: &SyncServer) -> &[String] {
    let config = &server.config;
    if config.kit_bundle_public_urls.is_empty() {
        config.oauth_resource_indicator.as_slice()
    } else {
        &config.kit_bundle_public_urls
    }
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
        description = "One signed slice request. No bearer: the signature is the authentication. It is the owner anchor's, of the recovery root a publisher named for the generation, over the vault, the root, the home's address (the host and port of one of its configured public URLs, or the URI authority or Host the request names, port included), the method, this path, the object, the generation, the offset, the time and the nonce.",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "The slice.", body = KitBundlePartResponse, content_type = "application/json"),
        (status = 409, description = "The generation's pad object is kept, and its bytes from the offset are not: the home awaits them again. Never a missing generation or the object's end.", body = KitPadObjectUnavailableResponse, content_type = "application/json"),
        (status = 400, description = "The body does not parse, a field is malformed, or neither the request nor any of the home's configured public URLs names a host.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "The request does not verify, no generation kept for the root matches, or the offset is at or past the object's end. All look the same.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "The sealed bundle read stopped.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(super) async fn part(
    State(server): State<Arc<SyncServer>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EnvelopedApiError> {
    let input: KitBundlePartRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("the kit fetch does not parse", None))?;
    let bad = |field: &str| ApiError::bad_request("the kit fetch field is malformed", Some(field));
    let mut origins = kit_origins(kit_public_urls(&server), &uri, &headers).into_iter();
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
    let vault = Arc::clone(server.vault());
    let object = fetch.object;
    let offset = fetch.offset;
    // A request that does not verify for one address takes no nonce, so each
    // other address checks it afresh, until one reads.
    let read = tokio::task::spawn_blocking(move || {
        let mut fetch = fetch;
        let mut read = kit_sealed_bundle_part(&vault, &fetch, &signature);
        for origin in origins {
            if read.is_ok() {
                break;
            }
            fetch.origin = origin;
            read = kit_sealed_bundle_part(&vault, &fetch, &signature);
        }
        read
    })
    .await
    .map_err(|_| ApiError::internal_server_error("the sealed bundle read stopped"))?;
    let Ok(Some((entry, read))) = read else {
        return Err(ApiError::not_found("sealed bundle", None).into());
    };
    let part = match read {
        BundlePartRead::Part(part) => part,
        BundlePartRead::End => return Err(ApiError::not_found("sealed bundle", None).into()),
        BundlePartRead::PadObjectUnavailable(unavailable) => {
            return Ok(pad_object_unavailable(&entry, &unavailable));
        }
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
    })
    .into_response())
}

/// The part door's typed answer for a kept pad object whose bytes the home
/// lacks (FIX 7106).
fn pad_object_unavailable(
    entry: &SealedBundleEntry,
    unavailable: &PadObjectUnavailable,
) -> Response {
    let body = KitPadObjectUnavailableResponse {
        outcome: BundlePartRead::PAD_OBJECT_UNAVAILABLE.to_owned(),
        generation: sealed_generation_hex(&unavailable.generation),
        object: SealedBundleObject::Pads.name().to_owned(),
        total: entry.pads_len,
        digest: sealed_digest_hex(&unavailable.digest),
        commit_order: entry.commit_order,
        offset: unavailable.offset,
    };
    (StatusCode::CONFLICT, Json(body)).into_response()
}

/// `POST /v1/recovery/sealed-bundle/index`: one page of the generations the
/// home keeps named for the kit's root, newest committed first, with the
/// revision of the one read that named them (FIX 7106) and the cursor of the
/// next page (FIX 9364). A request that does not verify and a root no kept
/// generation names look missing.
#[utoipa::path(
    post,
    path = "/v1/recovery/sealed-bundle/index",
    operation_id = "recovery_sealed_bundle_index",
    request_body(
        content = KitPadIndexRequest,
        description = "One signed index request. No bearer: the signature is the authentication. It is the owner anchor's, of the recovery root a publisher named for the newest generation kept for it, over the vault, the root, the home's address (as a part request signs it), the method, this path, the cursor (none for the first page), the time and the nonce.",
        content_type = "application/json"
    ),
    responses(
        (status = 200, description = "One page of the generations named for the root, and the next page's cursor when more follow.", body = KitPadIndexResponse, content_type = "application/json"),
        (status = 400, description = "The body does not parse, a field is malformed, or neither the request nor any of the home's configured public URLs names a host.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 404, description = "The request does not verify, or no kept generation names the root. Both look the same.", body = ApiErrorEnvelope, content_type = "application/json"),
        (status = 500, description = "The sealed bundle read stopped.", body = ApiErrorEnvelope, content_type = "application/json")
    )
)]
pub(super) async fn index(
    State(server): State<Arc<SyncServer>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<KitPadIndexResponse>, EnvelopedApiError> {
    let input: KitPadIndexRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("the kit fetch does not parse", None))?;
    let bad = |field: &str| ApiError::bad_request("the kit fetch field is malformed", Some(field));
    let mut origins = kit_origins(kit_public_urls(&server), &uri, &headers).into_iter();
    let fetch = KitPadIndexFetch {
        vault_id: parse_slip_id(&input.vault_id).map_err(|_| bad("vaultId"))?,
        root: RecoveryRootId(parse_slip_id(&input.root).map_err(|_| bad("root"))?),
        origin: origins
            .next()
            .ok_or_else(|| ApiError::bad_request("the request names no host", None))?,
        retained_revision: input
            .retained_revision
            .as_deref()
            .map(|revision| parse_slip_id(revision).map_err(|_| bad("retainedRevision")))
            .transpose()?,
        before_commit_order: input.before_commit_order,
        timestamp: input.timestamp,
        nonce: parse_slip_id(&input.nonce).map_err(|_| bad("nonce"))?,
    };
    let signature: [u8; 64] = parse_signature(&input.signature)
        .ok()
        .and_then(|signature| signature.try_into().ok())
        .ok_or_else(|| bad("signature"))?;
    let vault = Arc::clone(server.vault());
    // As for a part: each other address checks a request that did not verify.
    let read = tokio::task::spawn_blocking(move || {
        let mut fetch = fetch;
        let mut read = kit_sealed_bundle_index(&vault, &fetch, &signature);
        for origin in origins {
            if read.is_ok() {
                break;
            }
            fetch.origin = origin;
            read = kit_sealed_bundle_index(&vault, &fetch, &signature);
        }
        read
    })
    .await
    .map_err(|_| ApiError::internal_server_error("the sealed bundle read stopped"))?;
    let Ok(page) = read else {
        return Err(ApiError::not_found("sealed bundle", None).into());
    };
    let index = &page.index;
    Ok(Json(KitPadIndexResponse {
        retained_revision: sealed_digest_hex(&index.retained_revision),
        next_cursor: page
            .next_before_commit_order
            .map(|before_commit_order| KitPadIndexCursor {
                retained_revision: sealed_digest_hex(&index.retained_revision),
                before_commit_order,
            }),
        generations: index
            .entries
            .iter()
            .map(|entry| KitPadIndexEntry {
                generation: sealed_generation_hex(&entry.generation),
                commit_order: entry.commit_order,
                bundle_length: entry.bundle_len,
                bundle_digest: sealed_digest_hex(&entry.bundle_digest),
                pads_length: entry.pads_len,
                pads_digest: sealed_digest_hex(&entry.pads_digest),
            })
            .collect(),
    }))
}
