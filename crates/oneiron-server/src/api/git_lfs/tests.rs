//! LFS handler tests.

use super::*;
use crate::auth::mint_core_token_v2;
use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use axum::body::Body;
use axum::body::to_bytes;
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::Request;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::header::CONTENT_LENGTH;
use axum::http::header::CONTENT_TYPE;
use axum::http::header::HOST;
use oneiron::origin::lfs::LFS_JSON_MEDIA_TYPE;
use oneiron::origin::lfs::LfsOid;
use oneiron::origin::lfs::check_lfs_expectation;
use serde_json::Value;
use serde_json::json;
use std::sync::Arc;
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
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
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
    assert!(
        object.get("error").is_none(),
        "a live upload is not an error"
    );
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
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a digest mismatch is refused"
    );
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
        headers
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
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
            Body::from(serde_json::to_vec(&json!({"oid": oid, "size": 44})).expect("verify body")),
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
