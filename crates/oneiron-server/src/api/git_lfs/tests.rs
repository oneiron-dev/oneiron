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
async fn an_upload_with_no_declared_size_is_ended_at_the_disk_floor_without_waiting_for_its_end() {
    use axum::body::Bytes;
    use futures_util::StreamExt;
    use std::time::Duration;

    // A reserve no disk has: the floor is already reached.
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            disk_reserve_bytes: u64::MAX / 2,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let bytes = vec![b'x'; 2048];
    let oid = LfsOid::digest(&bytes);
    // The client never sends EOF or another frame, so the response must be
    // driven by the floor alone.
    let body = Body::from_stream(
        futures_util::stream::once(async move { Ok::<_, std::io::Error>(Bytes::from(bytes)) })
            .chain(futures_util::stream::pending()),
    );
    let (status, _, _) = tokio::time::timeout(
        Duration::from_secs(10),
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
    .expect("an upload at the floor does not wait for its body's end");
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
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

    vault
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
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
    let (want, token, world) = chunk_want(&server, &bytes);
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

/// `bytes` stored and attached to a note in a world, and a grant-scoped
/// chunk request for every one of its chunks from a viewer of that world:
/// the request, its bearer, and the world.
fn chunk_want(server: &Arc<SyncServer>, bytes: &[u8]) -> (Vec<u8>, String, oneiron::EntityId) {
    let oid = LfsOid::digest(bytes);
    let vault = server.vault();
    let at = oneiron::TimeRange {
        start: 1_700_000_000,
        end: 1_700_000_000,
    };
    vault.put_lfs_object(oid, bytes, at, at.start).unwrap();
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
            want: Some(
                vault
                    .lfs_manifest(oid)
                    .unwrap()
                    .expect("manifest")
                    .chunks
                    .iter()
                    .map(|chunk| chunk.hash)
                    .collect(),
            ),
        })
        .unwrap();
    let token = format!(
        "{}scope=core:read;principal_ref={}",
        crate::test_credentials::RECIPE_PREFIX,
        principal.to_hex()
    );
    (want, token, world)
}

/// `len` bytes that content-defined chunking cuts into many chunks.
fn varied_bytes(len: usize) -> Vec<u8> {
    let mut seed = 0x9e37_79b9_u32;
    (0..len)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 17;
            seed ^= seed << 5;
            seed.to_le_bytes()[0]
        })
        .collect()
}

/// Round 3 (Sol): a chunk reply keeps its transfer permit until it has been
/// taken, and gives it back once its client has stopped reading for the
/// idle limit.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chunk_reply_nobody_reads_gives_its_permit_back_at_the_idle_limit() {
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            lfs_transfers: 1,
            transfer_idle_timeout_ms: 300,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    // Many times the pieces a reply has in flight.
    let bytes = varied_bytes(1_000_000);
    let (want, token, _) = chunk_want(&server, &bytes);
    let exchange = |body: Vec<u8>| {
        crate::test_credentials::bind_request(
            &server,
            request(
                "POST",
                &format!("/git/{REPO}/info/lfs/chunks"),
                Some(&token),
                Body::from(body),
            ),
        )
    };
    let next = || {
        lfs_routes()
            .with_state(Arc::clone(&server))
            .oneshot(exchange(b"not a chunk request".to_vec()))
    };

    // Answered, and never read.
    let unread = lfs_routes()
        .with_state(Arc::clone(&server))
        .oneshot(exchange(want.clone()))
        .await
        .expect("route response");
    assert_eq!(unread.status(), StatusCode::OK);
    // A reply still being handed out holds its permit, so the next exchange
    // waits for it, and gets it at the idle limit.
    let started = std::time::Instant::now();
    let freed = tokio::time::timeout(PATIENCE, next())
        .await
        .expect("the unread reply gives its permit back")
        .expect("route response");
    assert_eq!(freed.status(), StatusCode::FORBIDDEN);
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(250),
        "it waited for the unread reply's permit"
    );
    drop(unread);

    // A reply that is read arrives whole.
    let read = lfs_routes()
        .with_state(Arc::clone(&server))
        .oneshot(exchange(want))
        .await
        .expect("route response");
    assert_eq!(read.status(), StatusCode::OK);
    let declared: usize = read.headers()[CONTENT_LENGTH]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    let body = to_bytes(read.into_body(), usize::MAX).await.expect("reply");
    assert!(body.len() == declared && declared > bytes.len());
}

/// Round 4 (Sol): a streamed chunk reply is judged again as each piece is
/// released, so a device-only flag committed after its head went out stops
/// the pieces still to come.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chunk_reply_stops_at_a_device_only_flag_set_while_it_streams() {
    let (_dir, server) = test_server(secret_config());
    let bytes = varied_bytes(1_000_000);
    let (want, token, world) = chunk_want(&server, &bytes);
    let request = crate::test_credentials::bind_request(
        &server,
        request(
            "POST",
            &format!("/git/{REPO}/info/lfs/chunks"),
            Some(&token),
            Body::from(want),
        ),
    );
    let response = lfs_routes()
        .with_state(Arc::clone(&server))
        .oneshot(request)
        .await
        .expect("route response");
    assert_eq!(response.status(), StatusCode::OK);

    server
        .vault()
        .keep_world_on_this_machine_under_for_test(
            &crate::test_credentials::host_issuer(&server),
            world,
            true,
        )
        .unwrap();
    assert!(
        to_bytes(response.into_body(), usize::MAX).await.is_err(),
        "no piece is released once the world is kept on this device"
    );
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

/// Rule five at the LFS rows: `row` crossed by `callers` uploads on one
/// credential (past a bound of one transfer, a quota of 16 bytes, or an
/// object size of 16 bytes) all land, and the row asks.
pub(crate) async fn cross_the_lfs_row(
    row: crate::wire_telemetry::LimitRow,
    callers: usize,
) -> crate::admission::Crossing {
    use crate::wire_telemetry::LimitRow;
    let mut config = secret_config();
    match row {
        LimitRow::LfsTransfers => config.limits.lfs_transfers = 1,
        LimitRow::LfsQuota => config.limits.lfs_quota_bytes = 16,
        LimitRow::LfsObjectSize => config.max_lfs_object_bytes = 16,
        other => panic!("{other:?} is not an LFS row"),
    }
    let (_dir, server) = test_server(config);
    let token = writer_token();
    let uploads: Vec<_> = (0..callers)
        .map(|n| {
            let server = Arc::clone(&server);
            let token = token.clone();
            tokio::spawn(async move {
                let bytes = format!("an object past the {row:?} row, number {n}").into_bytes();
                put(&server, &token, &bytes).await
            })
        })
        .collect();
    let mut refused = 0;
    for upload in uploads {
        if upload.await.unwrap() != StatusCode::OK {
            refused += 1;
        }
    }
    crate::admission::Crossing {
        refused,
        asked: asked(&server, row),
    }
}

/// Whether `row` asked whether everything is okay on this server.
fn asked(server: &Arc<SyncServer>, row: crate::wire_telemetry::LimitRow) -> bool {
    server
        .wire_telemetry
        .limit_questions()
        .latest(row)
        .is_some()
}

#[tokio::test]
async fn a_declaration_that_would_cross_the_disk_floor_is_refused_before_a_byte_is_read() {
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            disk_reserve_bytes: u64::MAX / 2,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let oid = LfsOid::digest(b"an object the disk has no room for");
    let never = Body::from_stream(futures_util::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >());
    let (status, _, _) = tokio::time::timeout(
        PATIENCE,
        route(&server, sized_put(&oid, &writer_token(), 1_024, never)),
    )
    .await
    .expect("refused on its declaration, without reading the body");
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(server.vault.lfs_object(oid).expect("record read"), None);
}

#[tokio::test]
async fn room_one_upload_has_claimed_on_the_disk_is_room_no_other_upload_can_take() {
    // Room past the reserve for one declared upload's spool and stored copy,
    // not for two. Each alone fits; the second must not count the first's
    // room as free (two uploads that both pass a free-space look and then
    // both write would take the disk below its reserve).
    const DECLARED: u64 = 256 * 1024 * 1024;
    let free = crate::machine::free_disk_bytes(&std::env::temp_dir()).expect("free space read");
    let Some(reserve) = free.checked_sub(3 * DECLARED) else {
        eprintln!(
            "under three declared uploads free in the temp dir; the floor is unprovable here"
        );
        return;
    };
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            disk_reserve_bytes: reserve,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let token = writer_token();
    let first = hold_upload(&server, &token, DECLARED).await;
    assert!(
        !first.is_finished(),
        "one upload has room for its spool and its stored copy"
    );

    let oid = LfsOid::digest(b"a second upload the disk has room for only alone");
    let never = Body::from_stream(futures_util::stream::pending::<
        Result<axum::body::Bytes, std::io::Error>,
    >());
    let (status, _, _) = tokio::time::timeout(
        PATIENCE,
        route(&server, sized_put(&oid, &token, DECLARED, never)),
    )
    .await
    .expect("refused on its declaration, without reading the body");
    assert_eq!(
        status,
        StatusCode::INSUFFICIENT_STORAGE,
        "the room the first upload claimed is not free for the second"
    );
    assert_eq!(
        put(&server, &token, b"a small object beside the held one").await,
        StatusCode::OK,
        "work that fits beside the claim still lands"
    );
    first.abort();
}

#[tokio::test]
async fn an_upload_past_the_object_size_row_lands_and_the_row_asks() {
    let config = SyncServerConfig {
        max_lfs_object_bytes: 1_024,
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let bytes = vec![b'x'; 4_096];
    assert_eq!(
        put(&server, &writer_token(), &bytes).await,
        StatusCode::OK,
        "the size row is a question, never a refusal"
    );
    assert!(asked(
        &server,
        crate::wire_telemetry::LimitRow::LfsObjectSize
    ));
    let stored = server
        .vault
        .lfs_object(LfsOid::digest(&bytes))
        .expect("record read");
    assert_eq!(stored.map(|object| object.size_bytes), Some(4_096));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_two_hundred_uploads_on_one_credential_all_complete() {
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            lfs_transfers: 4,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let token = writer_token();
    let uploads: Vec<_> = (0..200_u32)
        .map(|n| {
            let server = Arc::clone(&server);
            let token = token.clone();
            tokio::spawn(async move {
                let bytes = format!("burst object {n}").into_bytes();
                (put(&server, &token, &bytes).await, bytes)
            })
        })
        .collect();
    for upload in uploads {
        let (status, bytes) = tokio::time::timeout(std::time::Duration::from_secs(120), upload)
            .await
            .expect("every upload completes")
            .unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "a queued upload is served, never refused"
        );
        assert!(
            server
                .vault
                .lfs_object(LfsOid::digest(&bytes))
                .expect("record read")
                .is_some()
        );
    }
    assert!(asked(
        &server,
        crate::wire_telemetry::LimitRow::LfsTransfers
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn past_the_bound_an_upload_waits_its_turn_until_its_deadline() {
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            lfs_transfers: 1,
            queue_wait_timeout_ms: 400,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let token = writer_token();
    let held = hold_upload(&server, &token, 4_096).await;

    // Behind a held upload a second one waits, and its wait is a request
    // timeout: it ends there, nothing started.
    let started = std::time::Instant::now();
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
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(400),
        "it waited its deadline rather than being refused at once"
    );
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers["retry-after"], "1");
    assert_eq!(
        server
            .vault
            .lfs_object(LfsOid::digest(b"second"))
            .expect("record read"),
        None
    );

    // Once the held upload is gone, the next one is served.
    held.abort();
    let _ = held.await;
    assert_eq!(put(&server, &token, b"second").await, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chunk_exchange_waits_while_every_transfer_permit_is_held() {
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
    let exchange = {
        let server = Arc::clone(&server);
        tokio::spawn(async move {
            let request = request(
                "POST",
                &format!("/git/{REPO}/info/lfs/chunks"),
                Some(&token),
                Body::from(b"not a chunk request".to_vec()),
            );
            route(&server, request).await.0
        })
    };
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        !exchange.is_finished(),
        "the exchange waits for a permit; it is not refused"
    );

    // Once the permit is back the exchange reaches its own checks.
    held.abort();
    let _ = held.await;
    let status = tokio::time::timeout(PATIENCE, exchange)
        .await
        .expect("the exchange gets the permit back")
        .unwrap();
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_upload_past_the_quota_lands_and_the_quota_row_asks() {
    let config = SyncServerConfig {
        limits: crate::config::LimitsConfig {
            lfs_quota_bytes: 3_000,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let token = writer_token();

    // An upload in flight holds its declared size against the quota, so the
    // next one crosses it: it lands, and the row asks.
    let held = hold_upload(&server, &token, 2_000).await;
    assert!(!asked(&server, crate::wire_telemetry::LimitRow::LfsQuota));
    assert_eq!(put(&server, &token, &[b'a'; 1_500]).await, StatusCode::OK);
    assert!(asked(&server, crate::wire_telemetry::LimitRow::LfsQuota));
    held.abort();
    let _ = held.await;

    // Stored objects count in their own right; past them uploads still land.
    assert_eq!(put(&server, &token, &[b'b'; 2_000]).await, StatusCode::OK);
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
    assert_eq!(
        put(&server, &token, b"after the stall").await,
        StatusCode::OK
    );
}

/// Review r2 (Sol and Astra, P1): an upload with no declared size claimed no
/// room until its end, so between two looks at the disk it wrote up to 8 MiB
/// that no claim covered, and many such uploads at once took the disk
/// through its reserve. Each look now claims the piece in hand and all the
/// upload may write before its next look.
#[tokio::test]
async fn an_undeclared_upload_claims_what_it_may_write_before_its_next_look() {
    let (_dir, server) = test_server(secret_config());
    // Room past the reserve for 4 MiB: less than one look covers.
    server
        .transfers
        .disk
        .show_free(server.config.limits.disk_reserve_bytes + 4 * 1024 * 1024);
    let bytes = vec![b'x'; 2_048];
    let oid = LfsOid::digest(&bytes);
    let (status, _, _) = tokio::time::timeout(
        PATIENCE,
        route(
            &server,
            request(
                "PUT",
                &object_uri(&oid.to_hex()),
                Some(&writer_token()),
                stalled_body(bytes),
            ),
        ),
    )
    .await
    .expect("ended at its first look, without waiting for the rest of its body");
    assert_eq!(status, StatusCode::INSUFFICIENT_STORAGE);
    assert_eq!(
        put(&server, &writer_token(), b"a small declared object").await,
        StatusCode::OK,
        "an upload whose whole size fits still lands"
    );
}

/// Review r2 (Astra, P1): an upload with no declared size reserved the size
/// row against the quota and never more, so however far past the quota it
/// went, the quota row never asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_undeclared_upload_past_the_quota_lands_and_the_quota_row_asks() {
    let config = SyncServerConfig {
        max_lfs_object_bytes: 512,
        limits: crate::config::LimitsConfig {
            lfs_quota_bytes: 1_024,
            ..Default::default()
        },
        ..secret_config()
    };
    let (_dir, server) = test_server(config);
    let bytes = vec![b'q'; 2_048];
    let oid = LfsOid::digest(&bytes);
    let (status, _, _) = route(
        &server,
        request(
            "PUT",
            &object_uri(&oid.to_hex()),
            Some(&writer_token()),
            Body::from(bytes),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "past the quota an upload still lands"
    );
    assert!(
        asked(&server, crate::wire_telemetry::LimitRow::LfsQuota),
        "and the quota row asks"
    );
}
