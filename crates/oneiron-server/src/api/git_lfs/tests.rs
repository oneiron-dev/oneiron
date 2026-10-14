//! LFS handler tests.

use super::*;
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
    format!(
        "{}scope=core:read,core:write;principal_ref={}",
        crate::test_credentials::RECIPE_PREFIX,
        oneiron::EntityId::now().to_hex()
    )
}
fn reader_token() -> String {
    format!("{}scope=core:read", crate::test_credentials::RECIPE_PREFIX)
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
        builder = builder.header(AUTHORIZATION, token);
    }
    builder.body(body).expect("request")
}

async fn route(
    server: &Arc<SyncServer>,
    request: Request<Body>,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let request = crate::test_credentials::bind_request(server, request);
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
async fn lfs_over_cap_upload_refuses_without_waiting_for_body_eof() {
    use axum::body::Bytes;
    use futures_util::StreamExt;
    use std::time::Duration;

    let config = SyncServerConfig {
        max_lfs_object_bytes: 1024,
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let bytes = vec![b'x'; 2048];
    let oid = LfsOid::digest(&bytes);
    // The first frame crosses the cap. The client never sends EOF or another
    // frame, so the response must be driven by the worker's refusal alone.
    let body = Body::from_stream(
        futures_util::stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(bytes)) })
            .chain(futures_util::stream::pending()),
    );
    let (status, _, response) = tokio::time::timeout(
        Duration::from_secs(3),
        route(
            &server,
            request(
                "PUT",
                &object_uri(&oid.to_hex()),
                Some(&writer_token()),
                body,
            ),
        ),
    )
    .await
    .expect("over-cap upload must not wait for body EOF");
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let response = json_body(&response);
    assert_eq!(response["error"]["code"], "BAD_REQUEST");
    assert!(
        response["error"]["message"]
            .as_str()
            .is_some_and(|s| s.contains("object cap"))
    );
    assert_eq!(server.vault.lfs_object(oid).expect("record read"), None);
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
async fn lfs_upload_download_streams_past_sixteen_mib() {
    use futures_util::StreamExt;
    use sha2::{Digest, Sha256};
    let (_dir, server) = test_server(secret_config());
    let token = writer_token();
    let part = axum::body::Bytes::from(vec![0x5au8; 64 * 1024]);
    let count = 273usize;
    let mut hash = Sha256::new();
    for _ in 0..count {
        hash.update(&part);
    }
    let oid = LfsOid::from_bytes(hash.finalize().into());
    let stream =
        futures_util::stream::iter((0..count).map(move |_| Ok::<_, std::io::Error>(part.clone())));
    let response = lfs_routes()
        .with_state(Arc::clone(&server))
        .oneshot(crate::test_credentials::bind_request(
            &server,
            request(
                "PUT",
                &object_uri(&oid.to_hex()),
                Some(&token),
                Body::from_stream(stream),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = lfs_routes()
        .with_state(Arc::clone(&server))
        .oneshot(crate::test_credentials::bind_request(
            &server,
            request(
                "GET",
                &object_uri(&oid.to_hex()),
                Some(&reader_token()),
                Body::empty(),
            ),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers()[CONTENT_LENGTH],
        (count * 65536).to_string()
    );
    let mut stream = response.into_body().into_data_stream();
    let mut hash = Sha256::new();
    let mut size = 0usize;
    while let Some(part) = stream.next().await {
        let part = part.unwrap();
        assert!(part.len() <= oneiron::origin::lfs::LFS_CHUNK_MAX);
        size += part.len();
        hash.update(&part);
    }
    assert_eq!(size, count * 65536);
    let digest: [u8; 32] = hash.finalize().into();
    assert_eq!(&digest, oid.as_bytes());
}

#[tokio::test]
async fn lfs_unauthorized_stream_is_not_polled() {
    let (_dir, server) = test_server(secret_config());
    let unreadable = futures_util::stream::poll_fn(
        |_| -> std::task::Poll<Option<Result<axum::body::Bytes, std::io::Error>>> {
            panic!("unauthorized body must not be polled")
        },
    );
    let response = lfs_routes()
        .with_state(server)
        .oneshot(request(
            "PUT",
            &object_uri(&LfsOid::digest(b"x").to_hex()),
            None,
            Body::from_stream(unreadable),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn authenticated_interrupted_upload_consumes_prefix_without_publishing_object() {
    let (_dir, server) = test_server(secret_config());
    let token = writer_token();
    let prefix = axum::body::Bytes::from_static(b"valid prefix with a matching oid");
    let oid = LfsOid::digest(&prefix);
    let (sent, mut observed) = tokio::sync::oneshot::channel();
    let mut prefix = Some(prefix.clone());
    let mut sent = Some(sent);
    let stream = futures_util::stream::poll_fn(move |_| {
        if let Some(bytes) = prefix.take() {
            sent.take().unwrap().send(bytes.clone()).unwrap();
            std::task::Poll::Ready(Some(Ok::<_, std::io::Error>(bytes)))
        } else {
            std::task::Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "disconnected",
            ))))
        }
    });
    let (status, _, _) = route(
        &server,
        request(
            "PUT",
            &object_uri(&oid.to_hex()),
            Some(&token),
            Body::from_stream(stream),
        ),
    )
    .await;
    assert_eq!(
        observed.try_recv().unwrap().as_ref(),
        b"valid prefix with a matching oid"
    );
    assert!(!status.is_success());
    assert_ne!(status, StatusCode::UNAUTHORIZED);
    assert_ne!(status, StatusCode::FORBIDDEN);
    assert!(server.vault.lfs_object(oid).unwrap().is_none());
    let (status, _, _) = route(
        &server,
        request(
            "GET",
            &object_uri(&oid.to_hex()),
            Some(&reader_token()),
            Body::empty(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        upload(&server, &token, b"valid prefix with a matching oid").await,
        StatusCode::OK
    );
    assert!(server.vault.lfs_object(oid).unwrap().is_some());
}

/// Attaches the uploaded object `oid` only to a NOTE of a new, portable
/// world, and returns that world.
fn attach_to_a_note_in_a_world(vault: &oneiron::Vault, oid: LfsOid) -> oneiron::EntityId {
    let asset = vault.lfs_object(oid).unwrap().expect("object").asset_id;
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let note = vault
        .create_note(
            "research",
            "private attachment",
            oneiron::WriteActor::new(owner, oneiron::EdgeActorClass::Human),
        )
        .unwrap();
    let world = oneiron::EntityId::now();
    vault
        .put_entity(
            &world,
            oneiron::registry::ENTITY_TYPE_WORLD,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"private world",
        )
        .unwrap();
    vault
        .put_edge(&note, oneiron::EdgeKind::InWorld, &world, 1.0)
        .unwrap();
    vault
        .put_edge(&asset, oneiron::EdgeKind::Attached, &note, 1.0)
        .unwrap();
    world
}

/// Sol on #1402 (r9): an object attached only to a NOTE of a world turned
/// device-only is neither offered nor served by the Git-LFS download doors,
/// though it was downloadable while the world was portable.
#[tokio::test]
async fn lfs_download_withholds_an_object_only_a_device_only_world_owns() {
    let (_dir, server) = test_server(secret_config());
    let token = writer_token();
    let bytes = b"private attachment bytes".to_vec();
    let oid = LfsOid::digest(&bytes);
    let size = u64::try_from(bytes.len()).expect("length fits u64");
    assert_eq!(upload(&server, &token, &bytes).await, StatusCode::OK);
    let vault = server.vault();
    let world = attach_to_a_note_in_a_world(vault, oid);
    let get = || {
        request(
            "GET",
            &object_uri(&oid.to_hex()),
            Some(&token),
            Body::empty(),
        )
    };
    let batch = || {
        request(
            "POST",
            &format!("/git/{REPO}/info/lfs/objects/batch"),
            Some(&token),
            batch_body("download", &oid.to_hex(), size, &["basic"]),
        )
    };
    let (status, _, body) = route(&server, get()).await;
    assert_eq!((status, body), (StatusCode::OK, bytes));

    vault.set_world_device_only(world, true).unwrap();
    let (status, _, _) = route(&server, get()).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (_, _, body) = route(&server, batch()).await;
    let parsed = json_body(&body);
    assert!(parsed["objects"][0]["actions"]["download"].is_null());
    assert_eq!(parsed["objects"][0]["error"]["code"], LFS_BATCH_NOT_FOUND);
}

/// Astra #1402 re-check finding 2: a grant's chunk reply is judged again when
/// the handler releases it. A flag committed after the worker built the reply
/// returns none of the object's bytes.
#[tokio::test]
async fn a_chunk_reply_built_before_its_world_turns_device_only_is_not_released() {
    let (_dir, server) = test_server(secret_config());
    let bytes = b"private attachment bytes".to_vec();
    let oid = LfsOid::digest(&bytes);
    let vault = server.vault();
    let at = oneiron::TimeRange {
        start: 1_700_000_000,
        end: 1_700_000_000,
    };
    vault.put_lfs_object(oid, &bytes, at, at.start).unwrap();
    let world = attach_to_a_note_in_a_world(vault, oid);
    let principal = oneiron::EntityId::now();
    let grant_id = oneiron::EntityId::now();
    oneiron::sync::put_selector_test_federation_grant(
        vault,
        &grant_id,
        &oneiron::federation::FederationGrant::new(
            crate::handler::selector_grant_scope(),
            principal,
            oneiron::federation::FederationGrantRole::Viewer,
            oneiron::federation::FederationGrantPreset::ReadOnly,
        ),
        1,
    )
    .unwrap();
    let selector = oneiron::sync::encode_sync_selector(&oneiron::sync::SyncSelector::new(
        grant_id,
        principal,
        oneiron::sync::SyncSelectorWorld::All,
        vec![],
        vec![oneiron::federation::SelectorRange::Family(
            oneiron::registry::TypeByteFamily::Content,
        )],
    ))
    .unwrap();
    let want =
        oneiron::sync::chunks::encode_chunk_request(&oneiron::sync::chunks::ChunkSyncRequest {
            oid: *oid.as_bytes(),
            selector,
            have: vec![],
            want: Some(vec![
                vault.lfs_manifest(oid).unwrap().expect("manifest").chunks[0].hash,
            ]),
        })
        .unwrap();
    let token = format!(
        "{}scope=core:read;principal_ref={}",
        crate::test_credentials::RECIPE_PREFIX,
        principal.to_hex()
    );
    let exchange = || {
        request(
            "POST",
            &format!("/git/{REPO}/info/lfs/chunks"),
            Some(&token),
            Body::from(want.clone()),
        )
    };
    let carries = |body: &[u8]| body.windows(bytes.len()).any(|window| window == bytes);
    let (status, _, body) = route(&server, exchange()).await;
    assert!(status == StatusCode::OK && carries(&body));

    super::chunks::release_hook::arm(world);
    let (status, _, body) = route(&server, exchange()).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!carries(&body));
}

// -- storage admission (C6): finite by default, held by the worker ---------

/// Far past every idle limit these tests set.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(20);

/// A body that sends `head`, then never another byte nor its end.
fn stalled_body(head: Vec<u8>) -> Body {
    use futures_util::StreamExt;
    Body::from_stream(
        futures_util::stream::once(async move {
            Ok::<_, std::io::Error>(axum::body::Bytes::from(head))
        })
        .chain(futures_util::stream::pending()),
    )
}

/// An upload that declares its size, as a stock LFS client's does.
fn sized_put(oid: &LfsOid, token: &str, declared: u64, body: Body) -> Request<Body> {
    let mut request = request("PUT", &object_uri(&oid.to_hex()), Some(token), body);
    request
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from(declared));
    request
}

async fn put(server: &Arc<SyncServer>, token: &str, bytes: &[u8]) -> StatusCode {
    let oid = LfsOid::digest(bytes);
    let body = Body::from(bytes.to_vec());
    route(server, sized_put(&oid, token, bytes.len() as u64, body))
        .await
        .0
}

/// Starts an upload whose body stalls after a few bytes; it holds its permit
/// and its reservation until the task is aborted.
async fn hold_upload(
    server: &Arc<SyncServer>,
    token: &str,
    declared: u64,
) -> tokio::task::JoinHandle<StatusCode> {
    let server = Arc::clone(server);
    let request = sized_put(
        &LfsOid::digest(b"an upload that never finishes"),
        token,
        declared,
        stalled_body(vec![b'x'; 16]),
    );
    let held = tokio::spawn(async move { route(&server, request).await.0 });
    // Admission runs before the handler's first wait, so this is ample.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    held
}

/// Retries `call` while it answers `busy`: a worker returns what it held when
/// it ends, a moment after its client is gone.
async fn once_freed<F>(busy: StatusCode, mut call: impl FnMut() -> F) -> StatusCode
where
    F: std::future::Future<Output = StatusCode>,
{
    tokio::time::timeout(PATIENCE, async {
        loop {
            match call().await {
                status if status == busy => {
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                status => break status,
            }
        }
    })
    .await
    .expect("what a cancelled upload held comes back")
}

#[tokio::test]
async fn lfs_upload_declaring_more_than_the_default_cap_is_refused_before_a_byte_is_read() {
    let (_dir, server) = test_server(secret_config());
    let cap = SyncServerConfig::default().max_lfs_object_bytes;
    let oid = LfsOid::digest(b"an object too large to take");
    let never = Body::from_stream(futures_util::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >());
    let (status, _, body) = tokio::time::timeout(
        PATIENCE,
        route(&server, sized_put(&oid, &writer_token(), cap + 1, never)),
    )
    .await
    .expect("refused on its declaration, without reading the body");
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(json_body(&body)["error"]["code"], "PAYLOAD_TOO_LARGE");
    assert_eq!(server.vault.lfs_object(oid).expect("record read"), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lfs_uploads_past_a_principals_share_are_refused_while_one_is_held() {
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            lfs_transfers: 2,
            lfs_transfers_per_principal: 1,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let token = writer_token();
    let held = hold_upload(&server, &token, 4_096).await;

    let (status, headers, _) = route(
        &server,
        sized_put(
            &LfsOid::digest(b"second"),
            &token,
            6,
            Body::from(b"second".to_vec()),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "refused, not queued"
    );
    assert_eq!(headers["retry-after"], "1");
    assert_eq!(
        put(&server, &writer_token(), b"another principal").await,
        StatusCode::OK
    );

    held.abort();
    let _ = held.await;
    let freed = once_freed(StatusCode::SERVICE_UNAVAILABLE, || {
        put(&server, &token, b"second")
    })
    .await;
    assert_eq!(freed, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lfs_chunk_exchanges_are_refused_while_every_transfer_permit_is_held() {
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            lfs_transfers: 1,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let held = hold_upload(&server, &writer_token(), 4_096).await;

    let token = format!(
        "{}scope=core:read;principal_ref={}",
        crate::test_credentials::RECIPE_PREFIX,
        oneiron::EntityId::now().to_hex()
    );
    let exchange = || async {
        let request = request(
            "POST",
            &format!("/git/{REPO}/info/lfs/chunks"),
            Some(&token),
            Body::from(b"not a chunk request".to_vec()),
        );
        route(&server, request).await
    };
    let (status, headers, _) = exchange().await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "refused before its worker starts, not queued"
    );
    assert_eq!(headers["retry-after"], "1");

    // Once the permit is back the exchange reaches its own checks again.
    held.abort();
    let _ = held.await;
    let freed = once_freed(StatusCode::SERVICE_UNAVAILABLE, || async {
        exchange().await.0
    })
    .await;
    assert_eq!(freed, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lfs_quota_counts_stored_objects_and_uploads_in_flight() {
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            lfs_quota_bytes: 3_000,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let token = writer_token();
    let first = vec![b'a'; 1_500];

    // An upload in flight holds its declared size against the quota.
    let held = hold_upload(&server, &token, 2_000).await;
    assert_eq!(
        put(&server, &token, &first).await,
        StatusCode::INSUFFICIENT_STORAGE
    );
    held.abort();
    let _ = held.await;
    let freed = once_freed(StatusCode::INSUFFICIENT_STORAGE, || {
        put(&server, &token, &first)
    })
    .await;
    assert_eq!(freed, StatusCode::OK);

    // A stored object counts in its own right.
    assert_eq!(
        put(&server, &token, &[b'b'; 2_000]).await,
        StatusCode::INSUFFICIENT_STORAGE
    );
    assert_eq!(put(&server, &token, &[b'c'; 1_000]).await, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_lfs_upload_ends_at_the_idle_limit_and_frees_its_permit() {
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            lfs_transfers: 1,
            transfer_idle_timeout_ms: 300,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let token = writer_token();
    let held = hold_upload(&server, &token, 4_096).await;

    let status = tokio::time::timeout(PATIENCE, held)
        .await
        .expect("a body that stops arriving ends its upload")
        .unwrap();
    assert_ne!(status, StatusCode::OK);
    let freed = once_freed(StatusCode::SERVICE_UNAVAILABLE, || {
        put(&server, &token, b"after the stall")
    })
    .await;
    assert_eq!(freed, StatusCode::OK);
}
