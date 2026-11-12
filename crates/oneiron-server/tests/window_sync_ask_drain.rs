// Integration-test helpers (non-#[test] fns) are not covered by allow-unwrap-in-tests.
#![allow(clippy::unwrap_used)]
//! FIX 20468 (last part): the server drains the relayed ask intents a window
//! update landed, as the client lane does after its frames, with no ask
//! sweep. The home admitted an ask; its holder's relayed word names a result
//! row the home does not hold yet, so the intent waits there. The row comes
//! in through the window UPDATE arm, and the home consumes the intent then:
//! its result companion is committed (a refusal here, since the holder's
//! signature over the challenge is not a real one). Before the fix the
//! intent stayed pending until the next ask sweep, which a test server never
//! runs (`SyncServer::new` and `build_app` start no resident pump).
//!
//! `cargo test --locked -p oneiron-server --all-features --test window_sync_ask_drain`

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use loro::{ExportMode, LoroDoc};
use oneiron::authority::HostSlipIssuer;
use oneiron::sync::WindowKey;
use oneiron::sync::transport::{self, window_sub_tags};
use oneiron::task_verb::{
    AskForwardAct, AskForwardHolderProof, AskForwardReceipt, ConsultPayloadRef, TaskAskDefault,
    TaskAskQuestion, TaskAskSpec, TaskAskTarget, TaskAskWord, TaskAssignee,
};
use oneiron::{EdgeActorClass, EntityId, TimeRange};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

type WsStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const SECRET: &str = "ask-drain-secret";
/// The month window the result row lands in: 2026-03-15 00:00 UTC.
const WINDOW: &str = "2026-03";
const T0: u64 = 1_773_532_800;
/// The engine's call depth on a socket handler, as the served-door tests give it.
const STACK_BYTES: usize = 64 * 1024 * 1024;

fn open_vault(dir: &std::path::Path) -> Arc<oneiron::Vault> {
    Arc::new(oneiron::Vault::open(dir, oneiron::VaultConfig::device()).unwrap())
}

async fn spawn_server(
    vault: Arc<oneiron::Vault>,
) -> (SocketAddr, Arc<SyncServer>, tokio::task::JoinHandle<()>) {
    let config = SyncServerConfig {
        auth_secret: Some(SECRET.to_owned()),
        ..Default::default()
    };
    let server = Arc::new(SyncServer::new(vault, config).unwrap());
    let app = build_app(server.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, server, handle)
}

/// A host-root socket on the legacy full-window lane (as `tests/it/ws_sync.rs`
/// connects): a fresh proof for the logged root, then the protocol hello.
async fn connect_root(addr: SocketAddr, server: &SyncServer) -> WsStream {
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let slip = server.vault().ensure_host_root_slip(&issuer).unwrap();
    let timestamp = server.vault().now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let binding = serde_json::json!({"timestamp":timestamp,"nonce":nonce,"signature":signature});
    let mut request = format!("ws://{addr}/ws").into_client_request().unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", slip.to_token().unwrap())
            .parse()
            .unwrap(),
    );
    request
        .headers_mut()
        .insert("x-oneiron-binding", binding.to_string().parse().unwrap());
    let (mut ws, _response) = tokio_tungstenite::connect_async(request).await.unwrap();
    ws.send(Message::Binary(
        transport::encode_legacy_full_window_protocol_hello().into(),
    ))
    .await
    .unwrap();
    ws
}

/// The next binary frame (the root snapshot after the hello).
async fn next_binary(ws: &mut WsStream) -> Vec<u8> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("timed out waiting for a WebSocket message")
            .expect("WebSocket stream ended unexpectedly")
            .expect("WebSocket error");
        match msg {
            Message::Binary(data) => return data.to_vec(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("unexpected WebSocket message: {other:?}"),
        }
    }
}

/// Window bytes ride their pad envelope (FIX 7107): one pad-free envelope.
async fn send_enveloped_update(ws: &mut WsStream, key: &str, update: &[u8]) {
    let envelope = transport::WindowPadEnvelope {
        kind: transport::WindowPadKind::Update,
        form: transport::WindowPadForm::PadFree,
        queue_seq: None,
        payload: update.to_vec(),
        refs: Vec::new(),
        sidecar: None,
    };
    for frame in envelope
        .encode_frames(key, window_sub_tags::UPDATE)
        .unwrap()
    {
        ws.send(Message::Binary(frame.into())).await.unwrap();
    }
}

fn turn_body(role: &str) -> Vec<u8> {
    let mut body = Vec::new();
    rmpv::encode::write_value(
        &mut body,
        &rmpv::Value::Map(vec![(rmpv::Value::from("role"), rmpv::Value::from(role))]),
    )
    .unwrap();
    body
}

/// A slip of the home's own mint for `holder`: it parses and names its
/// holder, as the relayed intent's put requires.
fn holder_slip_token(server: &SyncServer, holder: EntityId) -> String {
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let root = server.vault().ensure_host_root_slip(&issuer).unwrap();
    let mut claims = root.claims;
    claims.slip_id = *blake3::hash(b"ask-drain-holder").as_bytes();
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = *blake3::hash(b"ask-drain-holder-key").as_bytes();
    server
        .vault()
        .mint_capability_slip(&issuer, claims)
        .unwrap()
        .to_token()
        .unwrap()
}

/// Polls `probe` for up to five seconds.
async fn eventually(mut probe: impl FnMut() -> bool) -> bool {
    for _ in 0..250 {
        if probe() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

#[test]
fn server_window_sync_drains_landed_ask_intents() {
    std::thread::Builder::new()
        .stack_size(STACK_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(STACK_BYTES)
                .enable_all()
                .build()
                .unwrap()
                .block_on(drains_landed_ask_intents());
        })
        .unwrap()
        .join()
        .expect("the test body passes");
}

async fn drains_landed_ask_intents() {
    let dir = tempfile::tempdir().unwrap();
    let vault = open_vault(dir.path());
    let (addr, server, handle) = spawn_server(vault.clone()).await;
    let mut socket = connect_root(addr, &server).await;
    let _ = next_binary(&mut socket).await; // root snapshot
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let token = holder_slip_token(&server, owner);

    // The home admits an ask; its owner is its responder.
    let question = EntityId::now();
    vault
        .put_entity(
            &question,
            oneiron::registry::ENTITY_TYPE_TURN,
            TimeRange { start: 2, end: 2 },
            2,
            &turn_body("question"),
        )
        .unwrap();
    let memory = vault.memory(owner, EdgeActorClass::Human);
    let ask = memory
        .tasks_ask(&TaskAskSpec {
            intent_key: "fix-20468-ask".into(),
            ..TaskAskSpec::shorthand(
                Some(TaskAskTarget::Responder(TaskAssignee::Human {
                    actor_ref: owner,
                })),
                TaskAskQuestion::new(
                    ConsultPayloadRef::parse(&vault, &format!("tn_{}", question.to_hex())).unwrap(),
                ),
                Some(u64::MAX),
                TaskAskDefault::AskMe,
            )
        })
        .unwrap();

    // The holder's relayed word names a result row the home does not hold.
    let result_row = EntityId::now();
    let receipt = memory
        .tasks_answer_forward(
            &ask.handle,
            "fix-20468-intent",
            &AskForwardAct::Word(TaskAskWord::new(result_row)),
            &AskForwardHolderProof {
                token,
                signature: "0".repeat(128),
            },
        )
        .unwrap();
    let intent_ref = match receipt {
        AskForwardReceipt::Pending { intent_ref } => intent_ref,
        other => panic!("the intent waits for its result row at the home: {other:?}"),
    };

    // The row comes in through the window UPDATE arm, from another node's
    // window of the same month.
    let peer_dir = tempfile::tempdir().unwrap();
    let peer = open_vault(peer_dir.path());
    peer.put_entity(
        &result_row,
        oneiron::registry::ENTITY_TYPE_TURN,
        TimeRange { start: T0, end: T0 },
        T0,
        &turn_body("answer"),
    )
    .unwrap();
    let doc = LoroDoc::new();
    let mirrored = oneiron::sync::window::reverse_rematerialize(
        &peer,
        &doc,
        &WindowKey::try_new(WINDOW).unwrap(),
    )
    .unwrap();
    assert!(mirrored >= 1, "the peer's window holds the result row");
    doc.commit();
    let update = doc.export(ExportMode::all_updates()).unwrap();
    send_enveloped_update(&mut socket, WINDOW, &update).await;
    let landed = eventually(|| vault.get_entity_type(&result_row).unwrap().is_some()).await;
    assert!(landed, "the window update lands the result row at the home");

    // No ask sweep runs on this server: only the UPDATE arm's drain consumes.
    let consumed = eventually(|| {
        !matches!(
            memory.tasks_answer_forward_status(intent_ref),
            Ok(AskForwardReceipt::Pending { .. })
        )
    })
    .await;
    assert!(
        consumed,
        "the home consumes the relayed intent once the window update landed its last row: {:?}",
        memory.tasks_answer_forward_status(intent_ref)
    );

    handle.abort();
}
