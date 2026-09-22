#![allow(clippy::unwrap_used)]
//! Full production socket + Hub + BoundSource + engine writes. No source override.
use super::production_tests::{ACTOR, AT, SECRET, server, token, witness};
use super::*;
use crate::server::SyncServer;
use futures_util::{SinkExt, StreamExt};
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

struct Fixture {
    task: tokio::task::JoinHandle<()>,
    server: Arc<SyncServer>,
    window: loro::LoroDoc,
    url: String,
    _dir: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture() -> Fixture {
    let (dir, server) = server();
    let window = server
        .get_or_create_window(&oneiron::sync::WindowKey::from_timestamp(AT))
        .await
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let app = crate::build_app(server.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Fixture {
        task,
        server,
        window,
        url,
        _dir: dir,
    }
}

fn materialize(f: &Fixture) {
    // Native LMDB-to-Loro mirror on the server's canonical window. This drives
    // its existing Observer B and production tee; no source or notification is injected.
    let mirrored = oneiron::sync::window::reverse_rematerialize(
        f.server.vault(),
        &f.window,
        &oneiron::sync::WindowKey::from_timestamp(AT),
    )
    .unwrap();
    assert!(mirrored > 0);
}

async fn next(socket: &mut Socket) -> Message {
    tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
}

async fn send(socket: &mut Socket, tag: u8, value: Value) {
    let bytes = test_wire::request(tag, value);
    socket.send(Message::Binary(bytes.into())).await.unwrap();
}

async fn app(socket: &mut Socket, tag: u8) -> Value {
    let mut collector = test_wire::Collector::default();
    // One deadline bounds the whole wait, even if sync broadcasts keep arriving.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Binary(bytes) if bytes[0] == tag => {
                    if let Some(value) = collector.feed(&bytes) {
                        return value;
                    }
                }
                Message::Binary(bytes) if !matches!(bytes[0], TAG_RPC | TAG_SUB) => {}
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("unexpected app frame: {other:?}"),
            }
        }
    })
    .await
    .unwrap()
}

async fn upgrade(f: &Fixture) -> Socket {
    let mut request = f.url.as_str().into_client_request().unwrap();
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {SECRET}").parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    socket
        .send(Message::Binary(
            vec![
                oneiron::sync::transport::TAG_PROTOCOL_HELLO,
                oneiron::sync::transport::PROTOCOL_VERSION,
            ]
            .into(),
        ))
        .await
        .unwrap();
    assert!(matches!(next(&mut socket).await, Message::Binary(ref bytes) if bytes[0] == 0));
    socket
}

async fn connect(f: &Fixture, class: &str) -> Socket {
    let mut socket = upgrade(f).await;
    send(
        &mut socket,
        TAG_RPC,
        json!({"requestId":7,"method":"auth.bind","params":crate::test_credentials::bind_payload(&f.server,&token(class))}),
    )
    .await;
    assert_eq!(
        app(&mut socket, TAG_RPC).await,
        json!({"requestId":7,"result":null,"last":true})
    );
    socket
}

async fn open(socket: &mut Socket, id: u64, query: &str, cursor: Value) {
    send(
        socket,
        TAG_SUB,
        json!({"method":"sub.open","subscriptionId":id,
        "scopedView":{"query":query},"cursor":cursor}),
    )
    .await;
}

async fn ack(socket: &mut Socket, id: u64, cursor: &Value) {
    send(
        socket,
        TAG_SUB,
        json!({"method":"sub.ack","subscriptionId":id,"cursor":cursor}),
    )
    .await;
}

async fn barrier(socket: &mut Socket) {
    send(
        socket,
        TAG_RPC,
        json!({"method":"hydrate","requestId":7,"params":{"refs":[]}}),
    )
    .await;
    assert_eq!(
        app(socket, TAG_RPC).await,
        json!({"requestId":7,"result":[],"last":true})
    );
}

async fn revoked_close(socket: &mut Socket) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Close(Some(close)) => {
                    assert_eq!(u16::from(close.code), 4008);
                    return;
                }
                Message::Binary(bytes) if !matches!(bytes[0], TAG_RPC | TAG_SUB) => {}
                Message::Ping(_) | Message::Pong(_) => {}
                other => panic!("revoked credential received data instead of close: {other:?}"),
            }
        }
    })
    .await
    .unwrap();
}

fn assert_snapshot(value: &Value, id: u64, count: usize) {
    assert_eq!(value["subscriptionId"], id, "{value}");
    assert!(
        matches!(value["kind"].as_str(), Some("snapshot" | "data")),
        "{value}"
    );
    assert_eq!(value["result"].as_array().unwrap().len(), count, "{value}");
    assert!(value.get("requestId").is_none());
    assert!(value.get("error").is_none());
    let cursor: Cursor = serde_json::from_value(value["cursor"].clone()).unwrap();
    loro::VersionVector::decode(&cursor.version_vector).unwrap();
}

#[tokio::test]
async fn production_socket_reads_and_subscribes_then_receives_materialized_engine_changes() {
    let f = fixture().await;
    let witnessed = witness(&f.server, "solar panel initial");
    let mut socket = connect(&f, "human").await;
    send(
        &mut socket,
        TAG_RPC,
        json!({"requestId":7,"method":"hydrate",
        "params":{"refs":witnessed.message_short_ids}}),
    )
    .await;
    let read = app(&mut socket, TAG_RPC).await;
    assert_eq!(read["requestId"], 7);
    assert_eq!(read["last"], true);
    assert_eq!(read["result"][0]["body"]["content"], "solar panel initial");
    open(&mut socket, 7, "solar", Value::Null).await;
    let initial = app(&mut socket, TAG_SUB).await;
    assert_snapshot(&initial, 7, 1);
    let message = f
        .server
        .vault()
        .memory(
            oneiron::EntityId::from_hex(ACTOR).unwrap(),
            oneiron::EdgeActorClass::Human,
        )
        .get_entity(&witnessed.message_short_ids[0])
        .unwrap()
        .unwrap();
    let message_id = oneiron::EntityId::from_hex(&message.id_hex).unwrap();
    let revision = f
        .server
        .vault()
        .indexed_revision(&message_id)
        .unwrap()
        .unwrap();
    let pinned_ref = format!("{}@{}", witnessed.message_short_ids[0], revision.to_hex());
    assert_eq!(initial["result"][0]["short_id"], pinned_ref);
    send(
        &mut socket,
        TAG_RPC,
        json!({"requestId":8,"method":"hydrate","params":{"refs":[pinned_ref]}}),
    )
    .await;
    let pinned = app(&mut socket, TAG_RPC).await;
    assert_eq!(pinned["requestId"], 8);
    assert_eq!(pinned["result"][0]["body"], read["result"][0]["body"]);
    ack(&mut socket, 7, &initial["cursor"]).await;
    barrier(&mut socket).await;
    witness(&f.server, "solar panel update");
    materialize(&f);
    let changed = app(&mut socket, TAG_SUB).await;
    assert_snapshot(&changed, 7, 2);
    assert_ne!(changed["cursor"], initial["cursor"]);
}

#[tokio::test]
async fn production_read_socket_closes_after_bound_jti_revocation() {
    let f = fixture().await;
    let mut socket = connect(&f, "agent").await;
    send(
        &mut socket,
        TAG_RPC,
        json!({"requestId":7,"method":"hydrate","params":{"refs":[ACTOR]}}),
    )
    .await;
    let read = app(&mut socket, TAG_RPC).await;
    assert_eq!(read["result"][0]["id_hex"], ACTOR);
    assert_eq!(read["last"], true);
    // Revoke the BOUND credential: each class mints a distinct slip, so
    // revoking a sibling class must not close this socket.
    crate::test_credentials::revoke(&f.server, &token("agent"));
    send(
        &mut socket,
        TAG_RPC,
        json!({"requestId":8,"method":"hydrate","params":{"refs":[ACTOR]}}),
    )
    .await;
    revoked_close(&mut socket).await;
}

#[tokio::test]
async fn production_subscription_revocation_closes_idle_socket_and_refuses_rebind() {
    let f = fixture().await;
    witness(&f.server, "solar panel subscription");
    let mut socket = connect(&f, "human").await;
    open(&mut socket, 7, "solar", Value::Null).await;
    let initial = app(&mut socket, TAG_SUB).await;
    assert_snapshot(&initial, 7, 1);
    crate::test_credentials::revoke(&f.server, &token("human"));
    // No further inbound app message is needed to enforce the revocation.
    revoked_close(&mut socket).await;
    let mut reconnected = upgrade(&f).await;
    send(
        &mut reconnected,
        TAG_RPC,
        json!({"requestId":7,"method":"auth.bind","params":crate::test_credentials::bind_payload(&f.server,&token("human"))}),
    )
    .await;
    revoked_close(&mut reconnected).await;
}

#[tokio::test]
async fn production_source_reconnect_replays_both_views_without_rpc_or_ack_duplicates() {
    let f = fixture().await;
    witness(&f.server, "solar panel initial");
    witness(&f.server, "lunar landing initial");
    let mut socket = connect(&f, "human").await;
    let mut cursors = Vec::new();
    for (id, query) in [(7, "solar"), (8, "lunar")] {
        open(&mut socket, id, query, Value::Null).await;
        let snapshot = app(&mut socket, TAG_SUB).await;
        assert_snapshot(&snapshot, id, 1);
        ack(&mut socket, id, &snapshot["cursor"]).await;
        cursors.push(snapshot["cursor"].clone());
    }
    barrier(&mut socket).await;
    drop(socket);
    witness(&f.server, "solar panel missed");
    witness(&f.server, "lunar landing missed");
    materialize(&f);
    let mut socket = connect(&f, "human").await;
    for ((id, query), cursor) in [(7, "solar"), (8, "lunar")].into_iter().zip(cursors) {
        open(&mut socket, id, query, cursor.clone()).await;
        let missed = app(&mut socket, TAG_SUB).await;
        assert_snapshot(&missed, id, 2);
        assert_ne!(missed["cursor"], cursor);
        ack(&mut socket, id, &missed["cursor"]).await;
    }
    barrier(&mut socket).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), app(&mut socket, TAG_SUB))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn production_cursor_cannot_be_reused_with_a_different_verified_class() {
    let f = fixture().await;
    let mut human = connect(&f, "human").await;
    open(&mut human, 7, "solar", Value::Null).await;
    let snapshot = app(&mut human, TAG_SUB).await;
    assert_snapshot(&snapshot, 7, 0);
    drop(human);
    let mut agent = connect(&f, "agent").await;
    open(&mut agent, 7, "solar", snapshot["cursor"].clone()).await;
    let refused = app(&mut agent, TAG_SUB).await;
    assert_eq!(refused["error"]["code"], "UNAUTHORIZED");
    assert_eq!(refused["last"], true);
    assert!(refused.get("result").is_none());
}

#[tokio::test]
async fn production_sub_errors_keep_engine_codes_and_scope_refusals_are_not_close_frames() {
    let f = fixture().await;
    let mut socket = connect(&f, "human").await;
    send(
        &mut socket,
        TAG_SUB,
        json!({"method":"sub.open","subscriptionId":7,
        "scopedView":{"query":"solar","facet":"zz999:ff"}}),
    )
    .await;
    let refused = app(&mut socket, TAG_SUB).await;
    let expected = f
        .server
        .vault()
        .memory(
            oneiron::EntityId::from_hex(ACTOR).unwrap(),
            oneiron::EdgeActorClass::Human,
        )
        .recall(
            "solar",
            Effort::Light,
            &RecallScope {
                world_ref: None,
                facet: Some("zz999:ff".to_owned()),
            },
            100,
            None,
            None,
        )
        .unwrap_err();
    assert_eq!(refused["error"]["code"], expected.code);
    assert_eq!(refused["error"]["message"], expected.message);
    assert_eq!(refused["error"]["suggestions"], json!(expected.suggestions));
    assert!(refused["error"]["requestId"].is_string());
    assert!(refused["error"].get("details").is_none());
    assert_eq!(refused["last"], true);
    assert!(refused.get("result").is_none());
    open(&mut socket, 7, "solar", Value::Null).await;
    assert_snapshot(&app(&mut socket, TAG_SUB).await, 7, 0);

    let mut write_only = upgrade(&f).await;
    let slip = format!("scope=core:write;principal_ref={ACTOR};actor_class=human");
    send(
        &mut write_only,
        TAG_RPC,
        json!({"requestId":7,"method":"auth.bind","params":crate::test_credentials::bind_payload(&f.server,&slip)}),
    )
    .await;
    assert_eq!(
        app(&mut write_only, TAG_RPC).await,
        json!({"requestId":7,"result":null,"last":true})
    );
    open(&mut write_only, 7, "solar", Value::Null).await;
    let refused = app(&mut write_only, TAG_SUB).await;
    assert_eq!(refused["error"]["code"], "FORBIDDEN");
    assert_eq!(refused["last"], true);
    assert!(refused.get("result").is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn established_socket_resumes_slim_on_work_but_not_keepalive() {
    use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
    use oneiron::outbound::*;
    struct Sink {
        socket: Socket,
        vault: Arc<oneiron::Vault>,
        runtime: tokio::runtime::Handle,
    }
    impl OutboundExecutionSink for Sink {
        fn execute(&mut self, _: &OutboundExecutionRequest<'_>) -> OutboundExecutionOutcome {
            self.vault
                .shed_rebuildable_heap(oneiron::ShedCause::LongOutboundWait, 2, 1000)
                .unwrap();
            assert_eq!(self.vault.residency(), oneiron::VaultResidency::Slim);
            self.runtime.block_on(async {
                self.socket
                    .send(Message::Ping(vec![1].into()))
                    .await
                    .unwrap();
                tokio::time::timeout(Duration::from_secs(5), async {
                    loop {
                        if matches!(next(&mut self.socket).await, Message::Pong(_)) {
                            break;
                        }
                    }
                })
                .await
                .unwrap();
                assert_eq!(self.vault.residency(), oneiron::VaultResidency::Slim);
                barrier(&mut self.socket).await;
                assert_eq!(self.vault.residency(), oneiron::VaultResidency::Full);
            });
            OutboundExecutionOutcome::delivered_to_channel("test-reply")
        }
    }
    let f = fixture().await;
    let socket = connect(&f, "human").await;
    let vault = f.server.vault().clone();
    // The outbound wait needs the seeded first-party ceiling as well as the
    // owner grant. The socket keeps its separate ordinary human principal.
    let actor_id = oneiron::EntityId::from_bytes([0xE1; 16]).unwrap();
    vault
        .put_entity(
            &actor_id,
            oneiron::registry::ENTITY_TYPE_PERSON,
            oneiron::TimeRange { start: 1, end: 1 },
            1,
            b"socket test sender",
        )
        .unwrap();
    vault
        .mint_standing_outbound_grant(
            &oneiron::EntityId::from_bytes([0xBC; 16]).unwrap(),
            &GrantMintIntent {
                principal_ref: actor_id.to_hex(),
                origin_component_id: "socket-slim-test".into(),
                origin_action_id: "escalate_always_this_verb_class".into(),
                origin_receipt_ref: None,
                scope: GrantMintIntentScope::VerbClass {
                    verb_class: "send".into(),
                },
            },
            2,
        )
        .unwrap();
    let runtime = tokio::runtime::Handle::current();
    tokio::task::spawn_blocking(move || {
        let actor = OutboundDispatchActor::agent(actor_id);
        let intent = OutboundIntent::from_trigger(
            OutboundIntentDraft::new(
                actor.actor_ref.as_deref().unwrap(),
                "send",
                "feedback_collector",
                "https://example.test/feedback",
            ),
            OutboundIntentTrigger::agent_immediate("approval"),
        );
        let request = OutboundDispatchRequest::new(
            "socket-slim",
            "socket-slim",
            intent,
            actor,
            OutboundDispatchGate::allow_when_policy_grants(),
            1000,
            OutboundDeliveryWindowDecision::DeliverNow,
        );
        let result = vault
            .dispatch_outbound_intent(
                request,
                &mut Sink {
                    socket,
                    vault: vault.clone(),
                    runtime,
                },
            )
            .unwrap();
        assert_eq!(result.outcome, OutboundDispatchOutcome::DeliveredToChannel);
    })
    .await
    .unwrap();
}
