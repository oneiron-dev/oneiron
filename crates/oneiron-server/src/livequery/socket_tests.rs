#![allow(clippy::unwrap_used)]
//! Real TCP/WebSocket ownership tests. Only the authority-bound read SOURCE
//! is replaced: production upgrade, bind, hub, control and send guards run.
//! No test actor class is injected into a token or into production auth.
use super::connection::Hub;
use super::subscriptions::*;
use super::*;
use crate::auth::mint_core_token_v2;
use crate::config::SyncServerConfig;
use crate::server::SyncServer;
use futures_util::{SinkExt, StreamExt};
use loro::LoroDoc;
use oneiron::sync::bridge::{LiveQueryTee, MaterializedDiffSummary, OriginMark};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

const SECRET: &str = "socket-reconnect-owner";
const ACTOR: &str = "11111111111111111111111111111111";
const OTHER: &str = "22222222222222222222222222222222";
const WORLD: &str = "33333333333333333333333333333333";
const WORLD_B: &str = "44444444444444444444444444444444";
type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Source {
    doc: LoroDoc,
    values: Mutex<BTreeMap<String, u64>>,
    derived: tokio::sync::watch::Sender<u64>,
    expired: std::sync::atomic::AtomicBool,
}

impl LiveQuerySource for Source {
    fn derive(&self, view: &ScopedView, _: Channel) -> Result<DerivedView, AppError> {
        let values = self.values.lock().unwrap();
        let world = view.world_ref.as_deref().unwrap_or(WORLD);
        let value = values.get(world).copied().unwrap_or(0);
        self.derived.send_replace(values.values().sum());
        Ok(DerivedView {
            value: json!(value),
            cursor: Cursor {
                document: "socket-fixture".into(),
                version_vector: self.doc.oplog_vv().encode(),
                batch: 0,
            },
            dependencies: BTreeSet::from([format!("world/{world}")]),
        })
    }
    fn can_resume(&self, cursor: &Cursor) -> Result<bool, AppError> {
        if cursor.document != "socket-fixture" {
            return Err(AppError::unauthorized());
        }
        if self.expired.load(std::sync::atomic::Ordering::Acquire) {
            return Ok(false);
        }
        export_since(&self.doc, cursor)
    }
}

struct Fixture {
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
    _server: Arc<SyncServer>,
    _hub: Arc<Hub>,
    source: Arc<Source>,
    queries: Arc<LiveQueries>,
    url: String,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn token(actor: &str) -> String {
    mint_core_token_v2(SECRET, &format!("scope=core:read;principal_ref={actor}"))
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(oneiron::Vault::open(dir.path(), oneiron::VaultConfig::device()).unwrap());
    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some(SECRET.into()),
                max_messages_per_sec: 10000,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let hub = Hub::for_server(&server);
    let auth =
        CoreAuth::from_bind_token(&token(ACTOR), &server.config, server.vault().as_ref()).unwrap();
    let source = Arc::new(Source {
        doc: LoroDoc::new(),
        values: Mutex::new(BTreeMap::new()),
        derived: tokio::sync::watch::channel(0).0,
        expired: std::sync::atomic::AtomicBool::new(false),
    });
    let queries = hub.install_source(auth, "socket-fixture".into(), source.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let app = crate::build_app(server.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Fixture {
        _dir: dir,
        task,
        _server: server,
        _hub: hub,
        source,
        queries,
        url,
    }
}

async fn next(socket: &mut Socket) -> Message {
    tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}
async fn send(socket: &mut Socket, tag: u8, value: Value) {
    let mut bytes = vec![tag];
    bytes.extend(serde_json::to_vec(&value).unwrap());
    socket.send(Message::Binary(bytes.into())).await.unwrap();
}
async fn app(socket: &mut Socket, tag: u8) -> Value {
    loop {
        match next(socket).await {
            Message::Binary(bytes) if bytes[0] == tag => {
                return serde_json::from_slice(&bytes[1..]).unwrap();
            }
            Message::Binary(bytes) if !matches!(bytes[0], TAG_RPC | TAG_SUB) => {}
            other => panic!("unexpected frame: {other:?}"),
        }
    }
}
async fn connect(f: &Fixture, actor: &str) -> Socket {
    let mut request = f.url.as_str().into_client_request().unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {SECRET}").parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    socket
        .send(Message::Binary(
            vec![
                oneiron::sync::transport::TAG_PROTOCOL_HELLO,
                oneiron::sync::transport::APP_TIER_PROTOCOL_VERSION_VERSION,
            ]
            .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(next(&mut socket).await, Message::Binary(ref bytes) if bytes[0] == 0));
    send(
        &mut socket,
        TAG_RPC,
        json!({"method":"auth.bind","requestId":7,"params":{"token":token(actor)}}),
    )
    .await;
    assert_eq!(
        app(&mut socket, TAG_RPC).await,
        json!({"requestId":7,"result":null,"last":true})
    );
    socket
}
async fn open(socket: &mut Socket, id: u64, world: &str, cursor: Value) {
    send(
        socket,
        TAG_SUB,
        json!({"method":"sub.open","subscriptionId":id,
        "scopedView":{"worldRef":world},"cursor":cursor}),
    )
    .await;
}
fn initial_cursor() -> Value {
    json!({"document":"socket-fixture","versionVector":loro::VersionVector::default().encode(),"batch":0})
}
async fn initial(socket: &mut Socket, id: u64, world: &str) -> Value {
    open(socket, id, world, initial_cursor()).await;
    assert_eq!(app(socket, TAG_SUB).await["kind"], "gap");
    let snapshot = app(socket, TAG_SUB).await;
    assert_eq!(snapshot["kind"], "snapshot");
    snapshot["cursor"].clone()
}
async fn write(f: &Fixture, world: &str, value: u64) {
    let mut observed = f.source.derived.subscribe();
    f.source.values.lock().unwrap().insert(world.into(), value);
    f.source
        .doc
        .get_map("worlds")
        .insert(world, value as i64)
        .unwrap();
    f.source.doc.commit();
    let target: u64 = f.source.values.lock().unwrap().values().sum();
    let path = format!("world/{world}");
    f.queries.on_materialized(
        &path,
        &MaterializedDiffSummary {
            containers: vec![path.clone()],
            bytes: 1,
        },
        &OriginMark::default(),
    );
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while *observed.borrow_and_update() != target {
            observed.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
}
async fn barrier(socket: &mut Socket) {
    send(
        socket,
        TAG_RPC,
        json!({"method":"not-a-read","requestId":7,"params":{}}),
    )
    .await;
    let reply = app(socket, TAG_RPC).await;
    assert_eq!(reply["requestId"], 7);
    assert_eq!(reply["last"], true);
}

#[tokio::test]
async fn socket_drop_rebind_replays_all_subs_without_rpc_or_acked_duplicates() {
    let f = fixture().await;
    let mut socket = connect(&f, ACTOR).await;
    let first = initial(&mut socket, 7, WORLD).await;
    let second = initial(&mut socket, 8, WORLD_B).await;
    send(
        &mut socket,
        TAG_SUB,
        json!({"method":"sub.ack","subscriptionId":7,"cursor":first}),
    )
    .await;
    send(
        &mut socket,
        TAG_SUB,
        json!({"method":"sub.ack","subscriptionId":8,"cursor":second}),
    )
    .await;
    barrier(&mut socket).await;
    write(&f, WORLD, 1).await;
    let seen = app(&mut socket, TAG_SUB).await;
    assert_eq!(seen["subscriptionId"], 7);
    send(
        &mut socket,
        TAG_SUB,
        json!({"method":"sub.ack","subscriptionId":7,"cursor":seen["cursor"]}),
    )
    .await;
    barrier(&mut socket).await;
    drop(socket); // abrupt TCP drop, not sub.close
    write(&f, WORLD, 2).await;
    write(&f, WORLD_B, 3).await;
    let mut socket = connect(&f, ACTOR).await;
    open(&mut socket, 7, WORLD, seen["cursor"].clone()).await;
    let missed_a = app(&mut socket, TAG_SUB).await;
    assert_eq!(missed_a["result"], 2);
    assert_eq!(missed_a["kind"], "snapshot");
    open(&mut socket, 8, WORLD_B, second).await;
    let missed_b = app(&mut socket, TAG_SUB).await;
    assert_eq!(missed_b["subscriptionId"], 8);
    assert_eq!(missed_b["result"], 3);
    assert_eq!(missed_b["kind"], "snapshot");
    barrier(&mut socket).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), socket.next())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn socket_reconnect_cannot_reuse_another_bound_authoritys_cursor() {
    let f = fixture().await;
    let mut owner = connect(&f, ACTOR).await;
    let cursor = initial(&mut owner, 7, WORLD).await;
    drop(owner);
    let mut other = connect(&f, OTHER).await;
    open(&mut other, 7, WORLD, cursor).await;
    let denied = app(&mut other, TAG_SUB).await;
    assert_eq!(denied["error"]["code"], "UNAUTHORIZED");
    assert!(denied.get("result").is_none());
}

#[tokio::test]
async fn production_sub_control_refuses_a_missing_verified_class() {
    let f = fixture().await;
    let mut socket = connect(&f, OTHER).await;
    send(
        &mut socket,
        TAG_SUB,
        json!({"method":"sub.close","subscriptionId":7}),
    )
    .await;
    barrier(&mut socket).await; // class-free close is not a NOT_IMPLEMENTED reply
    send(
        &mut socket,
        TAG_SUB,
        json!({"method":"sub.open","subscriptionId":7,"scopedView":{"worldRef":WORLD}}),
    )
    .await;
    let denied = app(&mut socket, TAG_SUB).await;
    assert_eq!(denied["error"]["code"], "FORBIDDEN");
    assert!(denied.get("result").is_none());
    assert_eq!(
        denied["error"]["message"],
        "facade routes bind writes to a declared actor class"
    );
    assert!(denied["error"]["requestId"].is_string());
    assert!(denied["error"].get("details").is_none());
}

#[tokio::test]
async fn socket_reconnect_past_retention_sends_gap_then_full_snapshot_once() {
    let f = fixture().await;
    let mut socket = connect(&f, ACTOR).await;
    let cursor = initial(&mut socket, 7, WORLD).await;
    drop(socket);
    write(&f, WORLD, 9).await;
    f.source
        .expired
        .store(true, std::sync::atomic::Ordering::Release);
    let mut socket = connect(&f, ACTOR).await;
    open(&mut socket, 7, WORLD, cursor).await;
    let gap = app(&mut socket, TAG_SUB).await;
    let snapshot = app(&mut socket, TAG_SUB).await;
    assert_eq!(gap["kind"], "gap");
    assert_eq!(snapshot["kind"], "snapshot");
    assert_eq!(snapshot["result"], 9);
    assert_eq!(gap["cursor"], snapshot["cursor"]);
    barrier(&mut socket).await;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), socket.next())
            .await
            .is_err()
    );
}
