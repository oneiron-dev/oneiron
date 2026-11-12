//! A sync client that carries a NOTE session accepts the home's `auth.bind`
//! reply (FIX-LIST [T0I-RESIDENCE-BIND-REPLY-STAMP-REFUSED]). Since FIX 811
//! the home states the bind's call receipt on that reply.

use ed25519_dalek::SigningKey;
use futures_util::{SinkExt, StreamExt};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::sync::bridge::Materializer;
use oneiron::sync::client::NoteSyncSession;
use oneiron::sync::transport::TAG_RPC;
use oneiron::sync::{SyncClient, SyncClientConfig, WindowManager};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

fn on_engine_threads<F, Fut>(test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let run = std::thread::Builder::new()
        .name("note-session-bind-reply".into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime")
                .block_on(test());
        })
        .expect("spawn engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

/// The reply envelope's keys and its `type`, for the failure messages.
fn reply_shape(payload: &[u8]) -> (Vec<String>, Option<String>) {
    let mut cursor = payload;
    let Ok(rmpv::Value::Map(fields)) = rmpv::decode::read_value(&mut cursor) else {
        return (Vec::new(), None);
    };
    let kind = fields
        .iter()
        .find(|(key, _)| key.as_str() == Some("type"))
        .and_then(|(_, value)| value.as_str())
        .map(str::to_owned);
    let keys = fields
        .iter()
        .filter_map(|(key, _)| key.as_str().map(str::to_owned))
        .collect();
    (keys, kind)
}

#[test]
fn a_note_session_client_accepts_the_homes_auth_bind_reply() {
    on_engine_threads(note_session_bind);
}

async fn note_session_bind() {
    let home_dir = tempfile::tempdir().expect("home dir");
    let device_dir = tempfile::tempdir().expect("device dir");
    let vault = Arc::new(Vault::open(home_dir.path(), VaultConfig::device()).expect("home vault"));
    let now = oneiron_vault_contract::now_ts();
    let actor = EntityId::now();
    vault
        .put_entity(
            &actor,
            oneiron::registry::ENTITY_TYPE_PERSON,
            TimeRange {
                start: now,
                end: now,
            },
            now,
            b"actor",
        )
        .expect("seed the session's person");
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("note-session-bind-reply-root".into()),
                ..Default::default()
            },
        )
        .expect("home server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");

    // The NOTE session: a read and write slip that names the person.
    let key = SigningKey::from_bytes(
        blake3::hash(b"oneiron/test-slip/binding/note-session-bind-reply").as_bytes(),
    );
    let mut claims = root.claims.clone();
    claims.slip_id = *blake3::hash(b"oneiron/test-slip/id/note-session-bind-reply").as_bytes();
    claims.parent_id = None;
    claims.holder_ref = actor.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("human".to_owned());
    claims.org_ref = None;
    claims.records = BTreeSet::new();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(["read", "write"].into_iter().map(str::to_owned).collect());
    claims.scope = scope;
    let slip = vault
        .mint_capability_slip(&issuer, claims)
        .expect("mint the session slip");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let url = format!(
        "ws://{}/ws",
        listener.local_addr().expect("listener address")
    );
    let app = build_app(Arc::clone(&server));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve the home");
    });

    // The upgrade proves the host root with a fresh holder signature.
    let mut request = url.as_str().into_client_request().expect("upgrade request");
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = issuer
        .binding_proof(&root, challenge.as_bytes())
        .expect("root holder proof")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", root.to_token().expect("root token"))
            .parse()
            .expect("authorization header"),
    );
    request.headers_mut().insert(
        "x-oneiron-binding",
        serde_json::json!({"timestamp": timestamp, "nonce": nonce, "signature": signature})
            .to_string()
            .parse()
            .expect("binding header"),
    );
    let (mut socket, _response) = tokio_tungstenite::connect_async(request)
        .await
        .expect("upgrade the sync socket");

    let device = Arc::new(Vault::open(device_dir.path(), VaultConfig::device()).expect("device"));
    let manager = Arc::new(WindowManager::new(
        device,
        Arc::new(Materializer::new()),
        "note-session-device",
    ));
    let (mut client, _events) = SyncClient::new(
        manager,
        SyncClientConfig {
            server_url: url,
            note_session: Some(NoteSyncSession::new(
                slip.to_token().expect("session token"),
                key,
            )),
            ..Default::default()
        },
    )
    .expect("sync client");
    // The opening frames: the hello, the NOTE session bind, the version vectors.
    for frame in client.generate_initial_sync() {
        socket
            .send(Message::Binary(frame.into()))
            .await
            .expect("send an opening frame");
    }

    let reply = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            match socket.next().await {
                Some(Ok(Message::Binary(frame))) if frame.first() == Some(&TAG_RPC) => {
                    return frame;
                }
                Some(Ok(Message::Close(close))) => {
                    panic!("the home closed the socket before the bind reply: {close:?}")
                }
                Some(Ok(_)) => {}
                other => panic!("the socket ended before the bind reply: {other:?}"),
            }
        }
    })
    .await
    .expect("the home answers the bind within 30 s");
    let (keys, kind) = reply_shape(&reply[1..]);
    eprintln!("auth.bind reply: type {kind:?}, keys {keys:?}");
    assert_eq!(
        kind.as_deref(),
        Some("rpc.res"),
        "the home refused the bind itself (keys {keys:?})"
    );
    if let Err(error) = client.handle_server_message(&reply) {
        panic!("the client refused the home's auth.bind reply (keys {keys:?}): {error:?}");
    }
}
