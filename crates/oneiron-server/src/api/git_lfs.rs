//! Git-LFS routes (ARCH-0068 Phase A, ONE-1909).
//!
//! Stock Git-LFS `basic` transfer and nothing else: batch negotiation, exact
//! body upload, download, and verify. The routes NEST inside the ONE-1908 git
//! router — there is no second router, no new token format, and no new
//! credential on the wire. The object plane itself lives in
//! [`oneiron::origin::lfs`]; this module owns the transport and the gate.
//!
//! # The gates
//!
//! | Route | Gate |
//! |---|---|
//! | `POST /git/{repo}/info/lfs/objects/batch` (download) | `Read` |
//! | `POST /git/{repo}/info/lfs/objects/batch` (upload) | `Write` + a registered `principal_ref` |
//! | `GET  /git/{repo}/info/lfs/objects/{oid}` | `Read` |
//! | `PUT/POST /git/{repo}/info/lfs/objects/{oid}` | `Write` + a registered `principal_ref` |
//! | `POST /git/{repo}/info/lfs/objects/{oid}/verify` | `Write` + a registered `principal_ref` |
//!
//! The write rows are the receive-pack rule read again: a bearer that carries
//! no `principal_ref` is authenticated but is not a REGISTERED actor, and the
//! unauthenticated-dev hatch mints exactly such an identity. No loopback branch
//! exists to take, because the gate never reads an address.
//!
//! `verify` sits on the write row deliberately. Its href is minted only inside
//! an upload batch, so it is an upload-flow endpoint; gating it lower would
//! publish a probe of what a vault holds to any read-scoped bearer.
//!
//! # Bodies are bounded here and only here
//!
//! [`LFS_MAX_OBJECT_BYTES`] is a named compile-time constant applied per route
//! through [`DefaultBodyLimit`]. Without it axum's 2 MiB default would silently
//! cap every LFS upload — the exact failure LFS exists to avoid. The limit is
//! transport-layer, so an oversized body is refused before the handler runs and
//! therefore before anything could be written; the handler's own gate is still
//! auth-first for every body that arrives.
//!
//! # Nothing is written on a mismatch, and nothing wrong is served
//!
//! An upload re-derives SHA-256 over the received bytes and compares it to the
//! `{oid}` the batch negotiated, plus the declared length when the client sent
//! one. A disagreement is a typed refusal BEFORE the engine is called. On the
//! way out, download and verify re-check the stored length and re-hash the
//! stored body: a corrupt body is an error, never `200 OK` with wrong bytes.

use crate::auth::CoreAuth;
use crate::auth::CoreScope;
use crate::error::ApiError;
use crate::error::EnvelopedApiError;
use crate::server::SyncServer;
use axum::Router;
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::extract::Path;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::CONTENT_LENGTH;
use axum::http::header::CONTENT_TYPE;
use axum::http::header::HOST;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::routing::post;
use oneiron::ErrorKind;
use oneiron::TimeRange;
use oneiron::origin::lfs::LFS_BASIC_TRANSFER;
use oneiron::origin::lfs::LFS_JSON_MEDIA_TYPE;
use oneiron::origin::lfs::LfsOid;
use oneiron::origin::lfs::check_lfs_expectation;
use serde::Deserialize;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

/// The largest LFS object body this origin accepts, per route.
///
/// A named constant rather than configuration on purpose: axum's default body
/// limit is 2 MiB, which would cap LFS uploads far below anything LFS is FOR,
/// and a silent cap is worse than a stated one. 16 MiB is the v1 default;
/// moving it wants a product reason, not a deployment knob.
pub(crate) const LFS_MAX_OBJECT_BYTES: usize = 16 * 1024 * 1024;

/// The media type a downloaded object body carries. LFS bytes are opaque: this
/// origin never guesses a content type for content it stores as a digest.
const LFS_OBJECT_MEDIA_TYPE: &str = "application/octet-stream";

/// Per-object failure codes the batch response speaks (Git-LFS batch API).
const LFS_BATCH_NOT_FOUND: u16 = 404;
const LFS_BATCH_UNPROCESSABLE: u16 = 422;

/// Builds the git-LFS routes. Merged into the ONE-1908 git router.
pub(crate) fn lfs_routes() -> Router<Arc<SyncServer>> {
    Router::new()
        .route("/git/{repo}/info/lfs/objects/batch", post(lfs_batch))
        .route(
            "/git/{repo}/info/lfs/objects/{oid}",
            get(lfs_download)
                .put(lfs_upload)
                .post(lfs_upload)
                .layer(DefaultBodyLimit::max(LFS_MAX_OBJECT_BYTES)),
        )
        .route("/git/{repo}/info/lfs/objects/{oid}/verify", post(lfs_verify))
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

/// What one LFS request needs to be allowed to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LfsAccess {
    /// Reads bytes this vault already holds.
    Read,
    /// Makes bytes durable, or probes an upload flow.
    Write,
}

/// Authenticates and authorizes one LFS request.
///
/// Split from the handlers so the gate is testable as itself, exactly as the
/// smart-HTTP gate is: the scope check and the registered-principal demand are
/// one function with no transport around them.
fn authorize(
    headers: &HeaderMap,
    server: &SyncServer,
    access: LfsAccess,
) -> Result<CoreAuth, ApiError> {
    let auth = CoreAuth::from_headers(headers, &server.config, server.vault().as_ref())?;
    auth.require(CoreScope::Read)?;
    if access == LfsAccess::Write {
        require_lfs_write(&auth)?;
    }
    Ok(auth)
}

/// The write half of the gate, over an already-authenticated actor.
///
/// A hatch-only identity and a bare trust-root secret both arrive here with
/// every scope and no `principal_ref`. Neither is a registered actor, so
/// neither may write — on 127.0.0.1 exactly as much as anywhere else.
fn require_lfs_write(auth: &CoreAuth) -> Result<(), ApiError> {
    auth.require(CoreScope::Write)?;
    auth.require_registered_principal()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------

/// The two batch operations Git-LFS defines.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
enum LfsBatchOperation {
    Upload,
    Download,
}

/// One `(oid, size)` pair a batch asks about.
#[derive(Clone, Debug, Deserialize)]
struct LfsBatchObject {
    oid: String,
    size: u64,
}

/// A Git-LFS batch request.
#[derive(Clone, Debug, Deserialize)]
struct LfsBatchRequest {
    operation: LfsBatchOperation,
    /// Absent means "the client did not narrow the transfer set", which stock
    /// clients spell by omitting the field. A non-empty set that does not name
    /// `basic` is a refusal: this origin serves one adapter.
    #[serde(default)]
    transfers: Vec<String>,
    objects: Vec<LfsBatchObject>,
}

#[derive(Debug, Serialize)]
struct LfsAction {
    href: String,
}

#[derive(Debug, Serialize)]
struct LfsObjectError {
    code: u16,
    message: &'static str,
}

#[derive(Debug, Serialize)]
struct LfsBatchResponseObject {
    oid: String,
    size: u64,
    authenticated: bool,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    actions: BTreeMap<&'static str, LfsAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<LfsObjectError>,
}

#[derive(Debug, Serialize)]
struct LfsBatchResponse {
    transfer: &'static str,
    objects: Vec<LfsBatchResponseObject>,
}

/// What an accepted upload made durable.
#[derive(Debug, Serialize)]
struct LfsUploadResponse {
    oid: String,
    size: u64,
}

#[derive(Clone, Debug, Deserialize)]
struct LfsVerifyRequest {
    oid: String,
    size: u64,
}

#[derive(Debug, Serialize)]
struct LfsVerifyResponse {
    oid: String,
    size: u64,
    ok: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /git/{repo}/info/lfs/objects/batch` — transfer negotiation.
pub(crate) async fn lfs_batch(
    State(server): State<Arc<SyncServer>>,
    Path(repo): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EnvelopedApiError> {
    // Read is the floor for reaching the object plane at all; the operation
    // the body names decides whether the write row applies as well.
    let auth = authorize(&headers, &server, LfsAccess::Read).map_err(EnvelopedApiError::from)?;
    let request: LfsBatchRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("lfs batch body is not a batch request", None))?;
    if request.operation == LfsBatchOperation::Upload {
        require_lfs_write(&auth).map_err(EnvelopedApiError::from)?;
    }
    let offers_basic = request
        .transfers
        .iter()
        .any(|transfer| transfer.as_str() == LFS_BASIC_TRANSFER);
    if !request.transfers.is_empty() && !offers_basic {
        return Err(ApiError::bad_request(
            "oneiron origin serves the basic LFS transfer only",
            Some("transfers"),
        )
        .into());
    }

    let base = href_base(&headers);
    let objects = request
        .objects
        .iter()
        .map(|object| batch_entry(&server, &base, &repo, request.operation, object))
        .collect::<Result<Vec<_>, ApiError>>()?;
    lfs_json_response(
        StatusCode::OK,
        &LfsBatchResponse {
            transfer: LFS_BASIC_TRANSFER,
            objects,
        },
    )
}

/// Answers one batch object: an action it can act on, or an honest error.
///
/// A download of an object this vault does not hold produces a per-object error
/// entry and NEVER a fabricated href: handing a client a link to bytes that do
/// not exist turns a clean 404 into a mid-transfer failure.
fn batch_entry(
    server: &SyncServer,
    base: &str,
    repo: &str,
    operation: LfsBatchOperation,
    object: &LfsBatchObject,
) -> Result<LfsBatchResponseObject, ApiError> {
    let mut entry = LfsBatchResponseObject {
        oid: object.oid.clone(),
        size: object.size,
        authenticated: true,
        actions: BTreeMap::new(),
        error: None,
    };
    let Ok(oid) = LfsOid::parse_hex(&object.oid) else {
        entry.error = Some(LfsObjectError {
            code: LFS_BATCH_UNPROCESSABLE,
            message: "oid is not a 64-character sha256",
        });
        return Ok(entry);
    };
    let stored = server
        .vault
        .has_lfs_object(oid, object.size)
        .map_err(|error| lfs_engine_error("lfs object lookup failed", &error))?;
    let href = format!("{base}/git/{repo}/info/lfs/objects/{}", oid.to_hex());
    match operation {
        LfsBatchOperation::Download if stored => {
            entry.actions.insert("download", LfsAction { href });
        }
        LfsBatchOperation::Download => {
            entry.error = Some(LfsObjectError {
                code: LFS_BATCH_NOT_FOUND,
                message: "object is not stored in this vault",
            });
        }
        // An object this vault already holds needs no upload action: the
        // client is told it is done, which is what makes dedup visible on the
        // wire instead of re-sending bytes.
        LfsBatchOperation::Upload if stored => {}
        LfsBatchOperation::Upload => {
            entry.actions.insert(
                "verify",
                LfsAction {
                    href: format!("{href}/verify"),
                },
            );
            entry.actions.insert("upload", LfsAction { href });
        }
    }
    Ok(entry)
}

/// `PUT|POST /git/{repo}/info/lfs/objects/{oid}` — exact body upload.
pub(crate) async fn lfs_upload(
    State(server): State<Arc<SyncServer>>,
    Path((_repo, oid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EnvelopedApiError> {
    authorize(&headers, &server, LfsAccess::Write).map_err(EnvelopedApiError::from)?;
    let oid = LfsOid::parse_hex(&oid)
        .map_err(|error| lfs_engine_error("lfs oid is not a 64-character sha256", &error))?;
    // The negotiated length when the client stated one. Both halves of the
    // expectation run before the engine is called, so a mismatch writes
    // nothing at all rather than writing and then repenting.
    check_lfs_expectation(oid, declared_size(&headers), &body)
        .map_err(|error| lfs_engine_error("lfs upload did not match its declaration", &error))?;
    let now = now_secs()?;
    let outcome = server
        .vault
        .put_lfs_object(
            oid,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .map_err(|error| lfs_engine_error("lfs object store failed", &error))?;
    lfs_json_response(
        StatusCode::OK,
        &LfsUploadResponse {
            oid: outcome.object.oid.to_hex(),
            size: outcome.object.size_bytes,
        },
    )
}

/// `GET /git/{repo}/info/lfs/objects/{oid}` — the stored bytes.
pub(crate) async fn lfs_download(
    State(server): State<Arc<SyncServer>>,
    Path((_repo, oid)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, EnvelopedApiError> {
    authorize(&headers, &server, LfsAccess::Read).map_err(EnvelopedApiError::from)?;
    let oid = LfsOid::parse_hex(&oid)
        .map_err(|error| lfs_engine_error("lfs oid is not a 64-character sha256", &error))?;
    // Re-checks length and re-hashes the body inside the engine. A corrupt
    // stored body raises here instead of being served as a success.
    let Some(bytes) = server
        .vault
        .get_lfs_object(oid)
        .map_err(|error| lfs_engine_error("lfs object read failed", &error))?
    else {
        return Err(ApiError::not_found("lfs object", Some(&oid.to_hex())).into());
    };
    Ok((
        StatusCode::OK,
        [(CONTENT_TYPE, LFS_OBJECT_MEDIA_TYPE)],
        bytes,
    )
        .into_response())
}

/// `POST /git/{repo}/info/lfs/objects/{oid}/verify` — the stored-bytes verdict.
pub(crate) async fn lfs_verify(
    State(server): State<Arc<SyncServer>>,
    Path((_repo, route_oid)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, EnvelopedApiError> {
    authorize(&headers, &server, LfsAccess::Write).map_err(EnvelopedApiError::from)?;
    let request: LfsVerifyRequest = serde_json::from_slice(&body)
        .map_err(|_| ApiError::bad_request("lfs verify body is not {oid, size}", None))?;
    let oid = LfsOid::parse_hex(&request.oid)
        .map_err(|error| lfs_engine_error("lfs oid is not a 64-character sha256", &error))?;
    // The route and the body both name an object; a verdict about a THIRD one
    // would be an answer to a question nobody asked.
    if LfsOid::parse_hex(&route_oid).ok() != Some(oid) {
        return Err(ApiError::bad_request(
            "lfs verify body names a different object than its route",
            Some("oid"),
        )
        .into());
    }
    let ok = server
        .vault
        .verify_lfs_object(oid, request.size)
        .map_err(|error| lfs_engine_error("lfs object verification failed", &error))?;
    lfs_json_response(
        StatusCode::OK,
        &LfsVerifyResponse {
            oid: oid.to_hex(),
            size: request.size,
            ok,
        },
    )
}

// ---------------------------------------------------------------------------
// Shared shapes
// ---------------------------------------------------------------------------

/// Maps an engine failure onto the wire without laundering it.
///
/// A declaration mismatch is the CLIENT's fault and says so; everything else —
/// corruption of a stored body included — is this origin's fault and is never
/// reported as a bad request, because a client cannot fix it by retrying with
/// different bytes.
fn lfs_engine_error(message: &'static str, error: &oneiron::Error) -> ApiError {
    match error.kind() {
        ErrorKind::InvalidLfsObject => ApiError::bad_request(error.to_string(), Some("oid")),
        _ => ApiError::internal_server_error(message),
    }
}

/// The length the client declared for this body, when it declared one.
fn declared_size(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
}

/// The absolute origin an action href is built from.
///
/// A stock LFS client follows absolute hrefs, so one is minted from the host
/// the request arrived at rather than from configuration this ticket does not
/// own. A request with no usable `Host` gets root-relative hrefs, which is the
/// honest answer: the origin cannot invent a hostname it was never told.
fn href_base(headers: &HeaderMap) -> String {
    let Some(host) = headers
        .get(HOST)
        .and_then(|value| value.to_str().ok())
        .filter(|host| !host.is_empty())
    else {
        return String::new();
    };
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .filter(|scheme| *scheme == "https")
        .unwrap_or("http");
    format!("{scheme}://{host}")
}

fn now_secs() -> Result<u64, ApiError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| ApiError::internal_server_error("system clock precedes the unix epoch"))
}

fn lfs_json_response(
    status: StatusCode,
    body: &impl Serialize,
) -> Result<Response, EnvelopedApiError> {
    let encoded = serde_json::to_vec(body)
        .map_err(|_| ApiError::internal_server_error("lfs response could not be serialized"))?;
    Ok((status, [(CONTENT_TYPE, LFS_JSON_MEDIA_TYPE)], encoded).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::mint_core_token_v2;
    use crate::config::SyncServerConfig;
    use axum::body::Body;
    use axum::body::to_bytes;
    use axum::http::HeaderValue;
    use axum::http::Request;
    use axum::http::header::AUTHORIZATION;
    use serde_json::Value;
    use serde_json::json;
    use tower::ServiceExt;

    const TRUST_ROOT: &str = "lfs-trust-root-secret";
    const REPO: &str = "demo.git";

    fn secret_config() -> SyncServerConfig {
        SyncServerConfig {
            auth_secret: Some(TRUST_ROOT.to_owned()),
            ..SyncServerConfig::default()
        }
    }

    /// The unauthenticated-dev hatch: every scope, no `principal_ref`.
    fn hatch_config() -> SyncServerConfig {
        SyncServerConfig {
            auth_secret: None,
            allow_unauthenticated: true,
            ..SyncServerConfig::default()
        }
    }

    fn test_server(config: SyncServerConfig) -> (tempfile::TempDir, Arc<SyncServer>) {
        let dir = tempfile::tempdir().expect("temp vault dir");
        let vault = Arc::new(
            oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).expect("open vault"),
        );
        let server = Arc::new(SyncServer::new(vault, config).expect("sync server"));
        (dir, server)
    }

    /// A registered principal is an entity id, so the fixture mints one rather
    /// than inventing a spelling the grammar would reject.
    fn writer_token() -> String {
        mint_core_token_v2(
            TRUST_ROOT,
            &format!(
                "scope=core:read,core:write;principal_ref={}",
                oneiron::EntityId::now().to_hex()
            ),
        )
    }

    fn reader_token() -> String {
        mint_core_token_v2(TRUST_ROOT, "scope=core:read")
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("bearer header"),
        );
        headers
    }

    fn request(method: &str, uri: &str, token: Option<&str>, body: Body) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(uri)
            .header(HOST, "origin.invalid");
        if let Some(token) = token {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        builder.body(body).expect("request")
    }

    async fn route(
        server: &Arc<SyncServer>,
        request: Request<Body>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = lfs_routes()
            .with_state(Arc::clone(server))
            .oneshot(request)
            .await
            .expect("route response");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        (status, headers, bytes.to_vec())
    }

    fn batch_body(operation: &str, oid: &str, size: u64, transfers: &[&str]) -> Body {
        Body::from(
            serde_json::to_vec(&json!({
                "operation": operation,
                "transfers": transfers,
                "objects": [{"oid": oid, "size": size}],
            }))
            .expect("batch body"),
        )
    }

    fn object_uri(oid: &str) -> String {
        format!("/git/{REPO}/info/lfs/objects/{oid}")
    }

    fn json_body(bytes: &[u8]) -> Value {
        serde_json::from_slice(bytes).expect("json response body")
    }

    async fn upload(server: &Arc<SyncServer>, token: &str, bytes: &[u8]) -> StatusCode {
        let oid = LfsOid::digest(bytes).to_hex();
        let (status, _, _) = route(
            server,
            request(
                "PUT",
                &object_uri(&oid),
                Some(token),
                Body::from(bytes.to_vec()),
            ),
        )
        .await;
        status
    }

    #[tokio::test]
    async fn lfs_batch_upload_returns_authenticated_actions() {
        let (_dir, server) = test_server(secret_config());
        let token = writer_token();
        let oid = LfsOid::digest(b"an object this vault does not hold yet").to_hex();

        let (status, headers, body) = route(
            &server,
            request(
                "POST",
                &format!("/git/{REPO}/info/lfs/objects/batch"),
                Some(&token),
                batch_body("upload", &oid, 38, &["basic"]),
            ),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
            Some(LFS_JSON_MEDIA_TYPE),
            "the batch answer is git-lfs JSON"
        );
        let body = json_body(&body);
        assert_eq!(body["transfer"], "basic");
        let object = &body["objects"][0];
        assert_eq!(object["oid"], oid.as_str());
        assert_eq!(object["authenticated"], true);
        assert_eq!(
            object["actions"]["upload"]["href"],
            format!("http://origin.invalid{}", object_uri(&oid)).as_str(),
            "the upload action addresses this origin's own object route"
        );
        assert_eq!(
            object["actions"]["verify"]["href"],
            format!("http://origin.invalid{}/verify", object_uri(&oid)).as_str()
        );
        assert!(object.get("error").is_none(), "a live upload is not an error");
    }

    #[tokio::test]
    async fn lfs_batch_download_returns_actions_and_transfer_basic() {
        let (_dir, server) = test_server(secret_config());
        let token = writer_token();
        let bytes = b"downloadable object bytes".to_vec();
        let oid = LfsOid::digest(&bytes).to_hex();
        let size = u64::try_from(bytes.len()).expect("length fits u64");
        assert_eq!(upload(&server, &token, &bytes).await, StatusCode::OK);

        let uri = format!("/git/{REPO}/info/lfs/objects/batch");
        let (status, _, body) = route(
            &server,
            request(
                "POST",
                &uri,
                Some(&token),
                batch_body("download", &oid, size, &["basic"]),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let parsed = json_body(&body);
        assert_eq!(parsed["transfer"], "basic");
        assert_eq!(
            parsed["objects"][0]["actions"]["download"]["href"],
            format!("http://origin.invalid{}", object_uri(&oid)).as_str()
        );

        // An object this vault does not hold gets an honest per-object error
        // instead of a fabricated href.
        let missing = LfsOid::digest(b"bytes nobody uploaded").to_hex();
        let (_, _, body) = route(
            &server,
            request(
                "POST",
                &uri,
                Some(&token),
                batch_body("download", &missing, 21, &["basic"]),
            ),
        )
        .await;
        let parsed = json_body(&body);
        assert_eq!(parsed["objects"][0]["error"]["code"], LFS_BATCH_NOT_FOUND);
        assert!(
            parsed["objects"][0]["actions"].is_null(),
            "a missing object is never handed an action"
        );

        // `basic` is the only transfer this origin serves.
        let (status, _, _) = route(
            &server,
            request(
                "POST",
                &uri,
                Some(&token),
                batch_body("download", &oid, size, &["tus", "multipart"]),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn lfs_upload_rejects_oid_and_size_mismatch() {
        let (_dir, server) = test_server(secret_config());
        let token = writer_token();
        let bytes = b"the bytes that were actually sent".to_vec();
        let claimed = LfsOid::digest(b"entirely different bytes");

        let (status, _, _) = route(
            &server,
            request(
                "PUT",
                &object_uri(&claimed.to_hex()),
                Some(&token),
                Body::from(bytes.clone()),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a digest mismatch is refused");
        assert_eq!(
            server.vault.lfs_object(claimed).expect("record read"),
            None,
            "and nothing was written for the claimed oid"
        );
        assert_eq!(
            server
                .vault
                .lfs_object(LfsOid::digest(&bytes))
                .expect("record read"),
            None,
            "nor for the real digest of the body"
        );

        // A declared length that disagrees with the body is refused by the same
        // shared gate, before the engine is reached.
        let honest = LfsOid::digest(&bytes);
        let mut headers = bearer(&token);
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("9999"));
        assert!(
            check_lfs_expectation(honest, declared_size(&headers), &bytes).is_err(),
            "a declared size that disagrees never reaches the engine"
        );
    }

    #[tokio::test]
    async fn lfs_upload_download_roundtrip_bytes_exact() {
        let (_dir, server) = test_server(secret_config());
        let token = writer_token();
        let bytes: Vec<u8> = (0..=255_u8).cycle().take(4096).collect();
        let oid = LfsOid::digest(&bytes).to_hex();
        assert_eq!(upload(&server, &token, &bytes).await, StatusCode::OK);

        let (status, headers, body) = route(
            &server,
            request("GET", &object_uri(&oid), Some(&token), Body::empty()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()),
            Some(LFS_OBJECT_MEDIA_TYPE)
        );
        assert_eq!(body, bytes, "download returns the uploaded bytes exactly");

        let (status, _, _) = route(
            &server,
            request(
                "GET",
                &object_uri(&LfsOid::digest(b"never uploaded").to_hex()),
                Some(&token),
                Body::empty(),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn lfs_verify_reports_ok_and_mismatch() {
        let (_dir, server) = test_server(secret_config());
        let token = writer_token();
        let bytes = b"verifiable object bytes".to_vec();
        let oid = LfsOid::digest(&bytes).to_hex();
        let size = u64::try_from(bytes.len()).expect("length fits u64");
        assert_eq!(upload(&server, &token, &bytes).await, StatusCode::OK);

        let verify = |oid: String, size: u64| {
            let server = Arc::clone(&server);
            let token = token.clone();
            async move {
                let (status, _, body) = route(
                    &server,
                    request(
                        "POST",
                        &format!("{}/verify", object_uri(&oid)),
                        Some(&token),
                        Body::from(
                            serde_json::to_vec(&json!({"oid": oid, "size": size}))
                                .expect("verify body"),
                        ),
                    ),
                )
                .await;
                (status, json_body(&body))
            }
        };

        let (status, body) = verify(oid.clone(), size).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(body["oid"], oid.as_str());
        assert_eq!(body["size"], size);

        let (_, body) = verify(oid, size + 1).await;
        assert_eq!(body["ok"], false, "a size that disagrees is not ok");

        let (_, body) = verify(LfsOid::digest(b"absent").to_hex(), 6).await;
        assert_eq!(body["ok"], false, "an absent object is not ok");
    }

    #[tokio::test]
    async fn lfs_unauthenticated_write_fails_including_loopback() {
        let (_dir, server) = test_server(secret_config());
        let bytes = b"bytes an unauthenticated caller may not store".to_vec();
        let oid = LfsOid::digest(&bytes).to_hex();

        for (method, uri, body) in [
            ("PUT", object_uri(&oid), Body::from(bytes.clone())),
            (
                "POST",
                format!("/git/{REPO}/info/lfs/objects/batch"),
                batch_body("upload", &oid, 44, &["basic"]),
            ),
            (
                "POST",
                format!("{}/verify", object_uri(&oid)),
                Body::from(
                    serde_json::to_vec(&json!({"oid": oid, "size": 44})).expect("verify body"),
                ),
            ),
        ] {
            let (status, _, _) = route(&server, request(method, &uri, None, body)).await;
            assert_eq!(
                status,
                StatusCode::UNAUTHORIZED,
                "{method} {uri} must refuse an unauthenticated caller"
            );
        }
        assert_eq!(
            server
                .vault
                .lfs_object(LfsOid::digest(&bytes))
                .expect("record read"),
            None,
            "and no refused request wrote anything"
        );

        // A read-scoped bearer is authenticated and still may not write.
        let (status, _, _) = route(
            &server,
            request(
                "PUT",
                &object_uri(&oid),
                Some(&reader_token()),
                Body::from(bytes),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // The dev hatch mints every scope and no principal_ref. It reaches
        // reads and can never reach a write, on 127.0.0.1 as much as anywhere:
        // the gate reads no address, so there is no loopback branch to take.
        let (_hatch_dir, hatch) = test_server(hatch_config());
        assert!(
            authorize(&HeaderMap::new(), &hatch, LfsAccess::Read).is_ok(),
            "the dev hatch still serves LFS reads"
        );
        assert_eq!(
            authorize(&HeaderMap::new(), &hatch, LfsAccess::Write)
                .expect_err("the dev hatch can never store an object")
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn lfs_upload_enforces_body_size_limit() {
        let (_dir, server) = test_server(secret_config());
        let token = writer_token();
        let oversized = vec![0x5a_u8; LFS_MAX_OBJECT_BYTES + 1];
        let oid = LfsOid::digest(&oversized);

        let (status, _, _) = route(
            &server,
            request(
                "PUT",
                &object_uri(&oid.to_hex()),
                Some(&token),
                Body::from(oversized),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::PAYLOAD_TOO_LARGE,
            "a body beyond LFS_MAX_OBJECT_BYTES is refused, not silently truncated"
        );
        assert_eq!(
            server.vault.lfs_object(oid).expect("record read"),
            None,
            "and the refused body wrote nothing"
        );

        // The limit is a stated bound, not axum's silent 2 MiB default: a body
        // far above that default still stores.
        let allowed = vec![0x5a_u8; 3 * 1024 * 1024];
        assert_eq!(
            upload(&server, &token, &allowed).await,
            StatusCode::OK,
            "3 MiB is past the framework default and well inside ours"
        );
    }
}
