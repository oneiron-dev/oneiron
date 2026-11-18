// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
// The counter lock is held, and two counts are reached, through test doors,
// which only the test command's `--cfg oneiron_test_support` compiles.
#![cfg(oneiron_test_support)]
//! Every wire count waits for the window's counter lock on the blocking
//! pool, never on a runtime worker (FIX
//! [WIRE-TELEMETRY-SYNC-PERSIST-ON-ASYNC-PATH]). A window rollover or a
//! threshold crossing keeps its rows through the vault under that lock, so a
//! count that waited for it on a worker held back every task on the worker.
//! Each test holds the lock, as a stalled persist holds it, and runs a
//! count on a runtime of one worker: a replication socket's sync frame, an
//! app-tier call on the socket, an e-sign QR capability refusal and an MCP
//! envelope error. Calls dropped while the lock is held leave at most
//! `MAX_PENDING_COUNTS` counts behind.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use oneiron::sync::transport::{PROTOCOL_VERSION, TAG_PROTOCOL_HELLO, TAG_RPC, TAG_VERSION_VECTOR};
use oneiron::{Vault, VaultConfig};
use oneiron_server::test_doors::off_router_wire_counts::{
    count_esign_capability_refusal, count_mcp_parse_error,
};
use oneiron_server::test_doors::one_click_wire_counter::while_wire_counter_held;
use oneiron_server::test_doors::wire_thresholds::set_thresholds;
use oneiron_server::wire_telemetry::{
    MAX_PENDING_COUNTS, WireTelemetry, WireThresholds, WireWindowReceipt,
};
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde::Serialize;
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const SECRET: &str = "wire-counts-off-runtime-owner";
/// A wire window no test outlasts.
const WINDOW_SECS: u64 = 604_800;
/// How long each test holds the counter lock before it lets go, when the
/// runtime's worker is free to let it go.
const HELD_FOR: Duration = Duration::from_secs(2);
/// How long the lock's holder waits for the runtime to let it go before it
/// lets go itself: a blocked worker never does.
const HOLDER_GIVES_UP_AFTER: Duration = Duration::from_secs(10);
/// The route an e-sign QR capability refusal counts under.
const ESIGN_REFUSAL_ROUTE: &str = "POST /esign/verify/report";
/// The category an MCP body that is not JSON counts under.
const MCP_PARSE_ERROR: &str = "parse_error";

/// Runs the future `test` makes to its end on a runtime of one worker
/// thread, on a thread with the engine's stack.
fn on_one_worker<T: Send + 'static, F: std::future::Future<Output = T>>(
    name: &str,
    test: impl FnOnce() -> F + Send + 'static,
) -> T {
    std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(test())
        })
        .unwrap()
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// A server on a fresh vault whose wire window is a week long and asks no
/// question, which admits an owner-grade socket under `SECRET`.
fn serve(dir: &tempfile::TempDir) -> (Arc<Vault>, Arc<SyncServer>) {
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let observer = WireTelemetry::new(Arc::clone(&vault));
    set_thresholds(
        &observer,
        &WireThresholds {
            window_secs: WINDOW_SECS,
            per_verb: u64::MAX,
            per_actor: u64::MAX,
        },
    )
    .unwrap();
    drop(observer);
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some(SECRET.to_owned()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    (vault, server)
}

/// The window kept for now, once the server that counted it has dropped
/// its counter: the counter keeps its window as it drops.
fn kept_window(vault: Arc<Vault>) -> WireWindowReceipt {
    let observer = WireTelemetry::new(vault);
    let start = oneiron_vault_contract::now_ts() / WINDOW_SECS * WINDOW_SECS;
    for _ in 0..50 {
        if let Some(window) = observer.receipt(start, start + WINDOW_SECS).unwrap() {
            return window;
        }
        // A count on the blocking pool may hold the counter for a moment
        // after the test drops the server.
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("the wire window was not kept");
}

/// Holds `server`'s counter lock on its own thread until the runtime sends
/// on the returned sender, or `HOLDER_GIVES_UP_AFTER` passes. The holder's
/// thread ends with whether the runtime let it go; this returns once the
/// lock is held.
fn hold_counter(
    server: &Arc<SyncServer>,
) -> (std::sync::mpsc::Sender<()>, std::thread::JoinHandle<bool>) {
    let (held_tx, held_rx) = std::sync::mpsc::channel::<()>();
    let (free_tx, free_rx) = std::sync::mpsc::channel::<()>();
    let holder = std::thread::spawn({
        let server = Arc::clone(server);
        move || {
            while_wire_counter_held(&server, move || {
                held_tx.send(()).unwrap();
                free_rx.recv_timeout(HOLDER_GIVES_UP_AFTER).is_ok()
            })
        }
    });
    held_rx.recv().unwrap();
    (free_tx, holder)
}

/// The host root slip's token and a fresh binding proof for it: an
/// owner-grade upgrade's two headers.
fn owner_upgrade(server: &SyncServer) -> (String, Value) {
    let issuer = oneiron::authority::HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let slip = server.vault().ensure_host_root_slip(&issuer).unwrap();
    let timestamp = server.vault().now_recorded_at();
    let nonce = oneiron::EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    (
        slip.to_token().unwrap(),
        json!({"timestamp":timestamp,"nonce":nonce,"signature":signature}),
    )
}

/// An owner-grade socket to `server` at `url`, past its hello: the server
/// has sent its root document.
async fn connect(server: &SyncServer, url: &str) -> Socket {
    let (token, binding) = owner_upgrade(server);
    let mut request = url.into_client_request().unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
        .headers_mut()
        .insert("x-oneiron-binding", binding.to_string().parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    socket
        .send(Message::Binary(
            vec![TAG_PROTOCOL_HELLO, PROTOCOL_VERSION].into(),
        ))
        .await
        .unwrap();
    let root = next_frame(&mut socket, Duration::from_secs(5)).await;
    assert!(
        matches!(root, Some(Message::Binary(ref data)) if data[0] == 0),
        "the server sends its root document after the hello: {root:?}"
    );
    socket
}

/// The next frame the server sends within `wait`, past pings and pongs, or
/// `None` once `wait` has passed. The wait is a runtime timer, so it ends
/// only while the runtime's worker is free.
async fn next_frame(socket: &mut Socket, wait: Duration) -> Option<Message> {
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, socket.next()).await {
            Err(_) => return None,
            Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
            Ok(Some(Ok(frame))) => return Some(frame),
            Ok(other) => panic!("the socket ended: {other:?}"),
        }
    }
}

/// The app envelope the server speaks: TAG + MessagePack
/// `{type, id, seq, last, payload}`, a request terminal at seq zero.
#[derive(Serialize)]
struct Envelope {
    #[serde(rename = "type")]
    kind: &'static str,
    id: u64,
    seq: u64,
    last: bool,
    payload: Value,
}

/// An RPC request frame: `method` with `params`, as request `id`.
fn rpc_frame(id: u64, method: &str, params: Value) -> Message {
    let envelope = Envelope {
        kind: "rpc.req",
        id,
        seq: 0,
        last: true,
        payload: json!({"method": method, "params": params}),
    };
    let mut data = vec![TAG_RPC];
    envelope
        .serialize(&mut rmp_serde::Serializer::new(&mut data).with_struct_map())
        .unwrap();
    Message::Binary(data.into())
}

/// A version-vector frame naming no change: a sync frame the replication
/// loop counts before it answers it.
fn version_vector_frame() -> Message {
    let mut data = vec![TAG_VERSION_VECTOR];
    data.extend_from_slice(&loro::VersionVector::default().encode());
    Message::Binary(data.into())
}

/// Sends `frame` on an owner-grade socket while the counter lock is held.
/// Whether the runtime's one worker stayed free while the frame's count
/// waited, and whether the server answered the frame before the lock was
/// let go.
async fn send_while_counter_held(frame: Message) -> (bool, bool) {
    let dir = tempfile::tempdir().unwrap();
    let (_vault, server) = serve(&dir);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let app = build_app(Arc::clone(&server));
    let serving = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let mut socket = connect(&server, &url).await;
    let (free_tx, holder) = hold_counter(&server);
    socket.send(frame).await.unwrap();
    // The frame's count waits for the lock, and the socket's loop answers
    // the frame only after its count. A count that waits on the worker
    // blocks this timer too, until the holder gives up.
    let answered_while_held = next_frame(&mut socket, HELD_FOR).await.is_some();
    let _ = free_tx.send(());
    let worker_was_free = holder.join().unwrap();
    serving.abort();
    (worker_was_free, answered_while_held)
}

/// While the counter lock is held, as a window rollover's persist holds
/// it, a replication socket's sync frame waits for its count on the
/// blocking pool: the runtime's one worker stays free, and the frame is
/// answered only once the count lands.
#[test]
fn a_sync_frame_count_waits_for_the_wire_counter_off_the_runtime_worker() {
    let (worker_was_free, answered_while_held) = on_one_worker("sync-frame-count-wait", || {
        send_while_counter_held(version_vector_frame())
    });
    assert!(
        worker_was_free,
        "the runtime's one worker stayed blocked while a sync frame's count waited for the wire counter"
    );
    assert!(
        !answered_while_held,
        "the sync frame was answered before its count landed"
    );
}

/// While the counter lock is held, an app-tier call on the socket (a bind,
/// which counts before it is judged) waits for its count on the blocking
/// pool: the runtime's one worker stays free, and the call is answered only
/// once the count lands.
#[test]
fn an_app_tier_call_count_waits_for_the_wire_counter_off_the_runtime_worker() {
    let (worker_was_free, answered_while_held) = on_one_worker("app-tier-count-wait", || {
        send_while_counter_held(rpc_frame(7, "auth.bind", json!({})))
    });
    assert!(
        worker_was_free,
        "the runtime's one worker stayed blocked while an app-tier call's count waited for the wire counter"
    );
    assert!(
        !answered_while_held,
        "the app-tier call was answered before its count landed"
    );
}

/// The count a test runs through a door, and where the kept window shows it.
#[derive(Clone, Copy)]
enum DoorCount {
    EsignRefusal,
    McpParseError,
}

impl DoorCount {
    async fn count(self, server: &SyncServer) {
        match self {
            Self::EsignRefusal => count_esign_capability_refusal(server).await,
            Self::McpParseError => count_mcp_parse_error(server).await,
        }
    }

    fn kept(self, window: &WireWindowReceipt) -> u64 {
        let counts = match self {
            Self::EsignRefusal => &window.capability_refusals,
            Self::McpParseError => &window.mcp_errors,
        };
        let key = match self {
            Self::EsignRefusal => ESIGN_REFUSAL_ROUTE,
            Self::McpParseError => MCP_PARSE_ERROR,
        };
        counts.get(key).copied().unwrap_or(0)
    }
}

/// Runs `door`'s count while the counter lock is held. Whether the
/// runtime's one worker stayed free while it waited, and how many of its
/// counts the kept window shows once the lock is let go.
async fn door_count_while_counter_held(door: DoorCount) -> (bool, u64) {
    let dir = tempfile::tempdir().unwrap();
    let (vault, server) = serve(&dir);
    let (free_tx, holder) = hold_counter(&server);
    let counting = tokio::spawn({
        let server = Arc::clone(&server);
        async move { door.count(&server).await }
    });
    // The count runs at this task's first wait. A count that waits on the
    // worker blocks this timer too, until the holder gives up.
    tokio::time::sleep(HELD_FOR).await;
    let _ = free_tx.send(());
    let worker_was_free = holder.join().unwrap();
    counting.await.unwrap();
    drop(server);
    (worker_was_free, door.kept(&kept_window(vault)))
}

/// While the counter lock is held, an e-sign QR capability refusal waits
/// for its count on the blocking pool, and the count lands once the lock
/// is free.
#[test]
fn an_esign_refusal_count_waits_for_the_wire_counter_off_the_runtime_worker() {
    let (worker_was_free, kept) = on_one_worker("esign-refusal-count-wait", || {
        door_count_while_counter_held(DoorCount::EsignRefusal)
    });
    assert!(
        worker_was_free,
        "the runtime's one worker stayed blocked while an e-sign refusal's count waited for the wire counter"
    );
    assert_eq!(kept, 1, "the refusal counts once the lock is free");
}

/// While the counter lock is held, an MCP envelope error waits for its
/// count on the blocking pool, and the count lands once the lock is free.
#[test]
fn an_mcp_envelope_error_count_waits_for_the_wire_counter_off_the_runtime_worker() {
    let (worker_was_free, kept) = on_one_worker("mcp-error-count-wait", || {
        door_count_while_counter_held(DoorCount::McpParseError)
    });
    assert!(
        worker_was_free,
        "the runtime's one worker stayed blocked while an MCP envelope error's count waited for the wire counter"
    );
    assert_eq!(kept, 1, "the envelope error counts once the lock is free");
}

/// E-sign refusals dropped while the counter lock is held, as a stalled
/// window persist holds it, leave at most `MAX_PENDING_COUNTS` counts
/// behind: a refusal past the bound waits for a count to end before it
/// hands its own to the blocking pool, and that wait ends with the call.
#[test]
fn dropped_refusals_leave_at_most_the_pending_count_bound_behind() {
    let kept = on_one_worker(
        "esign-refusal-dropped-counts",
        drop_refusals_while_counter_held,
    );
    assert_eq!(
        kept,
        u64::try_from(MAX_PENDING_COUNTS).unwrap(),
        "only the counts handed over before the refusals dropped land"
    );
}

/// How many refusals the kept window counts after more refusals than the
/// bound were dropped while the counter lock was held.
async fn drop_refusals_while_counter_held() -> u64 {
    let dir = tempfile::tempdir().unwrap();
    let (vault, server) = serve(&dir);
    let (release_tx, holder) = hold_counter(&server);
    let refusals: Vec<_> = (0..MAX_PENDING_COUNTS + 16)
        .map(|_| {
            let server = Arc::clone(&server);
            tokio::spawn(async move { count_esign_capability_refusal(&server).await })
        })
        .collect();
    // Every refusal runs to its count, or to its wait for a turn, while this
    // task sleeps (a slow test host gets room); then the callers go away.
    tokio::time::sleep(HELD_FOR).await;
    for refusal in &refusals {
        refusal.abort();
    }
    for refusal in refusals {
        let _ = refusal.await;
    }
    let _ = release_tx.send(());
    let _ = holder.join().unwrap();
    drop(server);
    DoorCount::EsignRefusal.kept(&kept_window(vault))
}
