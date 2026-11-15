// RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support,oneiron/test-hooks --test selector_release_recheck
#![cfg(oneiron_test_support)]
#![allow(clippy::unwrap_used, clippy::expect_used)]
//! Socket regressions for SELECTOR-RELEASE-POINT = B: a selector answer is
//! judged again where it leaves, so one queued before its grant is deleted,
//! narrowed or expires, or before its member's access grant is revoked,
//! never leaves. The test door
//! `oneiron_server::test_doors::selector_release::arm` runs its hook once,
//! as the next answer made under a grant is queued, after the answer is
//! made and before it can leave. A federation UPDATE whose basis changed
//! is not sent; a residence reply whose basis changed is replaced by an
//! RPC error with code RESULT_CHANGED.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use futures_util::{SinkExt, StreamExt};
use oneiron::access_grant::{
    AccessGrant, AccessGrantCapability, AccessGrantScope, AccessGrantStatus,
};
use oneiron::authority::{
    CapabilitySlip, ForwardedCallerProof, HostSlipIssuer, MachineOwnership, MachineRole,
};
use oneiron::claim::CallerLocality;
use oneiron::consent::AuthenticatedOwner;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{
    CoreferenceStatus, FederationGrant, FederationGrantPreset, FederationGrantRole, Scope,
    ScopeAxis, coreference_share_consent, own_device_residence_scope, put_coreference_link,
    unlink_coreference_link,
};
use oneiron::memory::{WitnessAuthor, WitnessMessage, WitnessTurn};
use oneiron::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP,
};
use oneiron::store::GateDecisionId;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::server_state::persist_window_snapshot;
use oneiron::sync::transport::{self, window_sub_tags};
use oneiron::sync::window::reverse_rematerialize;
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, encode_selector_vv_request, encode_sync_selector,
    put_selector_test_federation_grant,
};
use oneiron::test_doors::coreference_pact::bind_active_pact_to_grant;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::test_doors::selector_release::{arm, armed};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
const SECRET: &str = "selector-release-recheck";
const REPLY_WAIT: Duration = Duration::from_secs(10);
const WITHHELD_WAIT: Duration = Duration::from_secs(3);
/// How long after the fixture a test delegate grant expires: room for the
/// bind and the fetch to be answered before it.
const DELEGATE_LEAD_SECS: u64 = 6;

fn person(vault: &Vault, name: &str) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            &rmp_serde::to_vec_named(&json!({"name": name})).unwrap(),
        )
        .unwrap();
    id
}

struct Caller {
    slip: CapabilitySlip,
    key: SigningKey,
}

impl Caller {
    fn binding(&self, timestamp: u64) -> Value {
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let transcript = self.slip.binding_transcript(challenge.as_bytes()).unwrap();
        let signature: String = self
            .key
            .sign(&transcript)
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature})
    }

    fn bind_params(&self, timestamp: u64) -> Value {
        json!({"token": self.slip.to_token().unwrap(), "binding": self.binding(timestamp)})
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn mint(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    holder: EntityId,
    grant_id: EntityId,
    grant: &FederationGrant,
) -> Caller {
    let key = SigningKey::from_bytes(blake3::hash(EntityId::now().as_bytes()).as_bytes());
    let mut claims = root.claims.clone();
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.org_ref = None;
    claims.binding_key = key.verifying_key().to_bytes();
    claims.single_use = false;
    claims.records = BTreeSet::new();
    claims.channels.clear();
    claims.grant_ref = Some(grant_id.to_hex());
    claims.scope = grant.authority_scope.clone();
    Caller {
        slip: vault.mint_capability_slip(issuer, claims).unwrap(),
        key,
    }
}

struct Fixture {
    task: tokio::task::JoinHandle<()>,
    url: String,
    vault: Arc<Vault>,
    grant_id: EntityId,
    grant: FederationGrant,
    caller: Caller,
    selector: SyncSelector,
    window: WindowKey,
    item: EntityId,
    _dir: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    let member = person(&vault, "yuki");
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        own_device_residence_scope(),
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    put_selector_test_federation_grant(&vault, &grant_id, &grant, vault.now_recorded_at()).unwrap();
    let caller = mint(&vault, &issuer, &root, member, grant_id, &grant);
    let window = WindowKey::try_new("2026-03").unwrap();
    let at = window.start_timestamp().unwrap() + 86_400;
    let item = EntityId::now();
    vault
        .put_entity(
            &item,
            ENTITY_TYPE_FACET,
            TimeRange { start: at, end: at },
            at,
            &rmp_serde::to_vec_named(&json!({"title": "Selected facet"})).unwrap(),
        )
        .unwrap();
    let doc = create_window_doc("home", &window);
    reverse_rematerialize(&vault, &doc, &window).unwrap();
    persist_window_snapshot(&vault, &window, &doc).unwrap();
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![item], vec![]);
    // Startup discovers the persisted window; no pub(crate) server door is used.
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("ws://{}/ws", listener.local_addr().unwrap());
    let app = build_app(server);
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Fixture {
        task,
        url,
        vault,
        grant_id,
        grant,
        caller,
        selector,
        window,
        item,
        _dir: dir,
    }
}

fn host_root_binding(fx: &Fixture) -> (String, Value) {
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let slip = fx.vault.ensure_host_root_slip(&issuer).unwrap();
    let timestamp = fx.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    (
        slip.to_token().unwrap(),
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}),
    )
}

/// An owner-grade upgrade, the hello at `version`, and the root snapshot it
/// is answered with: the replication socket a selector or residence fetch
/// rides on this tree.
async fn upgrade(fx: &Fixture, version: u8) -> Socket {
    let mut request = fx.url.as_str().into_client_request().unwrap();
    let (token, binding) = host_root_binding(fx);
    request
        .headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
    request
        .headers_mut()
        .insert("x-oneiron-binding", binding.to_string().parse().unwrap());
    let (mut socket, _) = tokio_tungstenite::connect_async(request).await.unwrap();
    socket
        .send(Message::Binary(
            vec![transport::TAG_PROTOCOL_HELLO, version].into(),
        ))
        .await
        .unwrap();
    match next_message(&mut socket).await {
        Message::Binary(frame) => assert_eq!(frame[0], 0, "the first frame is the root snapshot"),
        other => panic!("the first frame must be the root snapshot, got {other:?}"),
    }
    socket
}

/// The member credential bound in band, as the federation and residence
/// lanes ask for it.
async fn bound(fx: &Fixture, version: u8) -> Socket {
    let mut socket = upgrade(fx, version).await;
    let bound = rpc(
        &mut socket,
        1,
        "auth.bind",
        fx.caller.bind_params(now_secs()),
    )
    .await;
    assert_eq!(
        bound,
        Value::Null,
        "same-slip bind has a terminal success reply"
    );
    socket
}

/// An arbitrary credential bound in band, as a forwarded search's carrier
/// binds its owner's before it forwards its caller's.
async fn bound_as(fx: &Fixture, version: u8, caller: &Caller) -> Socket {
    let mut socket = upgrade(fx, version).await;
    let bound = rpc(&mut socket, 1, "auth.bind", caller.bind_params(now_secs())).await;
    assert_eq!(
        bound,
        Value::Null,
        "same-slip bind has a terminal success reply"
    );
    socket
}

fn encoded_selector(selector: &SyncSelector) -> String {
    base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(selector).unwrap())
}

async fn send_binary(socket: &mut Socket, bytes: Vec<u8>) {
    socket.send(Message::Binary(bytes.into())).await.unwrap();
}

async fn next_message(socket: &mut Socket) -> Message {
    next_message_within(socket, REPLY_WAIT).await
}

async fn next_message_within(socket: &mut Socket, wait: Duration) -> Message {
    tokio::time::timeout(wait, socket.next())
        .await
        .expect("a reply or explicit close, never silence")
        .expect("socket did not end")
        .expect("valid WebSocket frame")
}

async fn next_binary_within(socket: &mut Socket, wait: Duration) -> Vec<u8> {
    loop {
        match next_message_within(socket, wait).await {
            Message::Binary(data) => return data.to_vec(),
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("expected a binary reply, got {other:?}"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    #[serde(rename = "type")]
    kind: String,
    id: u64,
    seq: u64,
    last: bool,
    payload: T,
}

async fn send_envelope(socket: &mut Socket, tag: u8, kind: &str, id: u64, payload: Value) {
    let envelope = Envelope {
        kind: kind.to_owned(),
        id,
        seq: 0,
        last: true,
        payload,
    };
    let mut bytes = vec![tag];
    envelope
        .serialize(&mut rmp_serde::Serializer::new(&mut bytes).with_struct_map())
        .unwrap();
    send_binary(socket, bytes).await;
}

async fn send_rpc(socket: &mut Socket, id: u64, method: &str, params: Value) {
    send_envelope(
        socket,
        transport::TAG_RPC,
        "rpc.req",
        id,
        json!({"method": method, "params": params}),
    )
    .await;
}

async fn rpc_reply_within(socket: &mut Socket, id: u64, wait: Duration) -> Result<Value, Value> {
    let mut bytes = Vec::new();
    let mut seq = 0;
    loop {
        let frame = next_binary_within(socket, wait).await;
        if frame[0] != transport::TAG_RPC {
            continue;
        }
        let head: Envelope<serde::de::IgnoredAny> = rmp_serde::from_slice(&frame[1..]).unwrap();
        assert_eq!(head.id, id);
        assert_eq!(head.seq, seq);
        if head.kind == "rpc.err" {
            assert_eq!(seq, 0);
            assert!(head.last);
            let error: Envelope<Value> = rmp_serde::from_slice(&frame[1..]).unwrap();
            return Err(error.payload);
        }
        assert_eq!(head.kind, "rpc.res");
        let chunk: Envelope<serde_bytes::ByteBuf> = rmp_serde::from_slice(&frame[1..]).unwrap();
        bytes.extend_from_slice(&chunk.payload);
        if head.last {
            return Ok(rmp_serde::from_slice(&bytes).unwrap());
        }
        seq += 1;
    }
}

async fn rpc(socket: &mut Socket, id: u64, method: &str, params: Value) -> Value {
    send_rpc(socket, id, method, params).await;
    rpc_reply_within(socket, id, REPLY_WAIT)
        .await
        .unwrap_or_else(|error| panic!("{method} refused: {error}"))
}

async fn send_window(socket: &mut Socket, key: &WindowKey, sub_tag: u8, payload: &[u8]) {
    send_binary(
        socket,
        transport::encode_window_sync(key.as_str(), sub_tag, payload)
            .into_result()
            .unwrap(),
    )
    .await;
}

/// Fails when a TAG_WINDOW_SYNC UPDATE for `window` arrives within 3 s;
/// every other frame is skipped.
async fn assert_no_update(socket: &mut Socket, window: &WindowKey) {
    let start = std::time::Instant::now();
    loop {
        let remaining = WITHHELD_WAIT.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return;
        }
        let message = match tokio::time::timeout(remaining, socket.next()).await {
            Err(_) => return,
            Ok(None) => panic!("the socket ended while the withheld UPDATE was owed silence"),
            Ok(Some(message)) => message.expect("valid WebSocket frame"),
        };
        match message {
            Message::Binary(data) => {
                if data.first() == Some(&transport::TAG_WINDOW_SYNC) {
                    if let Ok((key, tag, _)) = transport::decode_window_sync(&data[1..]) {
                        assert!(
                            !(key == window.as_str() && tag == window_sub_tags::UPDATE),
                            "a federation UPDATE left after its grant changed"
                        );
                    }
                }
            }
            Message::Ping(_) | Message::Pong(_) | Message::Text(_) => {}
            Message::Close(close) => {
                panic!("the socket closed while the withheld UPDATE was owed silence: {close:?}")
            }
            Message::Frame(_) => {}
        }
    }
}

/// The next TAG_WINDOW_SYNC UPDATE for `window`, skipping every other frame.
async fn wait_update(socket: &mut Socket, window: &WindowKey) -> Vec<u8> {
    let start = std::time::Instant::now();
    loop {
        let remaining = REPLY_WAIT.saturating_sub(start.elapsed());
        assert!(
            !remaining.is_zero(),
            "no UPDATE for {} arrived",
            window.as_str()
        );
        match next_message_within(socket, remaining).await {
            Message::Binary(data) => {
                if data.first() == Some(&transport::TAG_WINDOW_SYNC) {
                    if let Ok((key, tag, payload)) = transport::decode_window_sync(&data[1..]) {
                        if key == window.as_str() && tag == window_sub_tags::UPDATE {
                            return payload.to_vec();
                        }
                    }
                }
            }
            Message::Ping(_) | Message::Pong(_) | Message::Text(_) => {}
            Message::Close(close) => {
                panic!("the socket closed before the UPDATE arrived: {close:?}")
            }
            Message::Frame(_) => {}
        }
    }
}

#[test]
fn a_selector_update_queued_before_its_grant_is_deleted_never_leaves() {
    run_on_engine_stack("selector-release-delete", || async {
        let fx = fixture().await;
        let vault = Arc::clone(&fx.vault);
        let grant = fx.grant_id;
        arm(grant, move || {
            vault.delete_entity(&grant).unwrap();
        });
        assert!(armed(&grant), "the hook is armed before the fetch");
        let mut socket = bound(&fx, transport::PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::SELECTOR_VV_REQUEST,
            &encode_selector_vv_request(&fx.selector, &[]).unwrap(),
        )
        .await;
        assert_no_update(&mut socket, &fx.window).await;
        assert!(!armed(&grant), "the hook ran as the answer was queued");
    });
}

#[test]
fn a_selector_update_queued_before_its_grant_narrows_never_leaves() {
    run_on_engine_stack("selector-release-narrow", || async {
        let fx = fixture().await;
        let vault = Arc::clone(&fx.vault);
        let grant = fx.grant_id;
        let before = fx.grant.clone();
        arm(grant, move || {
            let mut narrow = before.clone();
            narrow.authority_scope.bands = ScopeAxis::Some(BTreeSet::from([ENTITY_TYPE_CLAIM]));
            put_selector_test_federation_grant(&vault, &grant, &narrow, vault.now_recorded_at())
                .unwrap();
        });
        assert!(armed(&grant), "the hook is armed before the fetch");
        let mut socket = bound(&fx, transport::PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::SELECTOR_VV_REQUEST,
            &encode_selector_vv_request(&fx.selector, &[]).unwrap(),
        )
        .await;
        assert_no_update(&mut socket, &fx.window).await;
        assert!(!armed(&grant), "the hook ran as the answer was queued");
    });
}

#[test]
fn a_residence_reply_queued_before_its_grant_is_deleted_is_refused() {
    run_on_engine_stack("selector-release-residence", || async {
        let fx = fixture().await;
        let vault = Arc::clone(&fx.vault);
        let grant = fx.grant_id;
        arm(grant, move || {
            vault.delete_entity(&grant).unwrap();
        });
        assert!(armed(&grant), "the hook is armed before the call");
        let mut socket = bound(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        send_rpc(
            &mut socket,
            2,
            "residence.index",
            json!({
                "window": fx.window.as_str(),
                "selector": encoded_selector(&fx.selector),
                "limit": 16
            }),
        )
        .await;
        let error = rpc_reply_within(&mut socket, 2, REPLY_WAIT)
            .await
            .expect_err("a reply queued before its grant was deleted is refused, never a result");
        assert_eq!(error["code"], "RESULT_CHANGED", "{error}");
        assert!(!armed(&grant), "the hook ran as the answer was queued");
    });
}

/// Waits until the hook has held its answer as long as it means to, so the
/// silence that follows is the release's, never the hook's.
async fn wait_held(held: &AtomicBool) {
    let start = std::time::Instant::now();
    while !held.load(Ordering::SeqCst) {
        assert!(
            start.elapsed() < REPLY_WAIT + Duration::from_secs(2 * DELEGATE_LEAD_SECS),
            "the hook never ran: no answer was queued"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[test]
fn a_selector_update_queued_before_its_delegate_grant_expires_never_leaves() {
    run_on_engine_stack("selector-release-expiry", || async {
        let fx = fixture().await;
        // An expiry changes neither the grant's bytes nor the authority
        // fold, yet past it the grant confers no read (Sol review F1).
        let member = fx.grant.member_ref;
        let delegate_id = EntityId::now();
        let expires_at = fx.vault.now_recorded_at() + DELEGATE_LEAD_SECS;
        let mut delegate = FederationGrant::new(
            own_device_residence_scope(),
            member,
            FederationGrantRole::Delegate,
            FederationGrantPreset::Delegate,
        );
        delegate.expires_at = Some(expires_at);
        delegate.delegated_by = Some(person(&fx.vault, "aiko"));
        put_selector_test_federation_grant(
            &fx.vault,
            &delegate_id,
            &delegate,
            fx.vault.now_recorded_at(),
        )
        .unwrap();
        let selector = SyncSelector::new(
            delegate_id,
            member,
            SyncSelectorWorld::All,
            vec![fx.item],
            vec![],
        );
        let held = Arc::new(AtomicBool::new(false));
        let vault = Arc::clone(&fx.vault);
        let done = Arc::clone(&held);
        arm(delegate_id, move || {
            // Holds the answer in its queue until the expiry second has come.
            let deadline = std::time::Instant::now() + Duration::from_secs(2 * DELEGATE_LEAD_SECS);
            while vault.now_recorded_at() < expires_at && std::time::Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(100));
            }
            done.store(true, Ordering::SeqCst);
        });
        let mut socket = bound(&fx, transport::PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::SELECTOR_VV_REQUEST,
            &encode_selector_vv_request(&selector, &[]).unwrap(),
        )
        .await;
        wait_held(&held).await;
        assert!(
            fx.vault.now_recorded_at() >= expires_at,
            "the delegate grant expired while its answer was queued"
        );
        assert_no_update(&mut socket, &fx.window).await;
    });
}

#[test]
fn a_selector_answer_whose_grant_stands_leaves() {
    run_on_engine_stack("selector-release-guard", || async {
        let fx = fixture().await;
        let mut socket = bound(&fx, transport::PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::SELECTOR_VV_REQUEST,
            &encode_selector_vv_request(&fx.selector, &[]).unwrap(),
        )
        .await;
        let update = wait_update(&mut socket, &fx.window).await;
        assert!(
            !update.is_empty(),
            "the standing grant's UPDATE carries the selected window"
        );
        let mut residence = bound(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        let index = rpc(
            &mut residence,
            2,
            "residence.index",
            json!({
                "window": fx.window.as_str(),
                "selector": encoded_selector(&fx.selector),
                "limit": 16
            }),
        )
        .await;
        assert_eq!(index["items"][0]["entity_id"], fx.item.to_hex(), "{index}");
    });
}

#[test]
fn a_forwarded_search_reply_queued_before_its_callers_access_grant_is_revoked_is_refused() {
    run_on_engine_stack("selector-release-forwarded", || async {
        let fx = fixture().await;
        fx.vault
            .install_device_keystore(Arc::new(MemoryKeystore::new()));
        let owner = fx.vault.ensure_embedded_owner_actor().unwrap();
        let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
        let root = fx.vault.ensure_host_root_slip(&issuer).unwrap();
        fx.vault
            .ensure_serving_install_profile(&issuer, MachineRole::Owned(MachineOwnership::Yours))
            .unwrap();
        let grant_id = EntityId::now();
        let grant = FederationGrant::new(
            own_device_residence_scope(),
            owner,
            FederationGrantRole::Owner,
            FederationGrantPreset::Owner,
        );
        put_selector_test_federation_grant(
            &fx.vault,
            &grant_id,
            &grant,
            fx.vault.now_recorded_at(),
        )
        .unwrap();
        let owner_caller = mint(&fx.vault, &issuer, &root, owner, grant_id, &grant);
        let caller_person = person(&fx.vault, "caller");
        let caller_grant_id = EntityId::now();
        let caller_grant = FederationGrant::new(
            own_device_residence_scope(),
            caller_person,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        );
        put_selector_test_federation_grant(
            &fx.vault,
            &caller_grant_id,
            &caller_grant,
            fx.vault.now_recorded_at(),
        )
        .unwrap();
        let caller = mint(
            &fx.vault,
            &issuer,
            &root,
            caller_person,
            caller_grant_id,
            &caller_grant,
        );
        let relationship = EntityId::now();
        fx.vault
            .put_entity(
                &relationship,
                ENTITY_TYPE_RELATIONSHIP,
                TimeRange { start: 1, end: 1 },
                1,
                b"a relationship space",
            )
            .unwrap();
        let access = EntityId::now();
        fx.vault
            .create_access_grant(
                &access,
                &AccessGrant {
                    principal_ref: caller_person,
                    scope: AccessGrantScope::Messages {
                        space_ref: relationship,
                    },
                    capability: AccessGrantCapability::MessagesRead,
                    authority_scope: Scope::top(),
                    status: AccessGrantStatus::Active,
                    created_at: 1,
                    revoked_at: None,
                    expires_at: None,
                    companion_bounds: None,
                },
            )
            .unwrap();
        let at = fx.window.start_timestamp().unwrap() + 86_400;
        let room = EntityId::now();
        let turn = EntityId::now();
        fx.vault
            .memory(owner, EdgeActorClass::Human)
            .witness(&WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: None,
                messages: vec![WitnessMessage {
                    id: None,
                    author: WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: "harbor view table for two".to_owned(),
                    parts: None,
                    metadata: Some(json!({"rel": relationship.to_hex()})),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: at,
                assertions: Default::default(),
            })
            .unwrap();
        let doc = create_window_doc("home", &fx.window);
        reverse_rematerialize(&fx.vault, &doc, &fx.window).unwrap();
        persist_window_snapshot(&fx.vault, &fx.window, &doc).unwrap();
        let selector = SyncSelector::new(grant_id, owner, SyncSelectorWorld::All, vec![], vec![]);
        let selector_wire = encode_sync_selector(&selector).unwrap();
        let token = caller.slip.to_token().unwrap();
        let timestamp = now_secs();
        let binding = caller.binding(timestamp);
        let forwarded = ForwardedCallerProof {
            token,
            timestamp,
            nonce: binding["nonce"].as_str().unwrap().to_owned(),
            signature: binding["signature"].as_str().unwrap().to_owned(),
        };
        let locality = CallerLocality::OnDevice;
        let machine_proof = oneiron::sync::residence::with_forwarded_search_page(
            "harbor",
            16,
            &selector_wire,
            None,
            None,
            None,
            locality,
            None,
            |request| {
                fx.vault
                    .forwarding_machine_proof(request, &forwarded)
                    .unwrap()
                    .expect("the install forwards its caller's search")
            },
        );
        let vault = Arc::clone(&fx.vault);
        arm(grant_id, move || {
            vault
                .revoke_access_grant(&access, vault.now_recorded_at())
                .unwrap();
        });
        assert!(armed(&grant_id), "the hook is armed before the call");
        let mut socket = bound_as(&fx, transport::RESIDENCE_PROTOCOL_VERSION, &owner_caller).await;
        let mut params = json!({
            "query": "harbor",
            "limit": 16,
            "selector": encoded_selector(&selector),
        });
        params["forwarded"] = serde_json::to_value(&forwarded).unwrap();
        params["machine_proof"] = serde_json::to_value(&machine_proof).unwrap();
        params["caller_locality"] = serde_json::to_value(&locality).unwrap();
        send_rpc(&mut socket, 2, "residence.search", params).await;
        let error = rpc_reply_within(&mut socket, 2, REPLY_WAIT)
            .await
            .expect_err("a reply queued before its caller's grant was revoked is refused");
        assert_eq!(error["code"], "RESULT_CHANGED", "{error}");
        assert!(!armed(&grant_id), "the hook ran as the answer was queued");
    });
}

#[test]
fn a_selector_update_carrying_a_message_its_members_revoked_grant_admits_never_leaves() {
    run_on_engine_stack("selector-release-member-message", || async {
        let fx = fixture().await;
        // The member's relationship reach is an access grant, stored outside
        // the authority log: its revocation leaves the selector grant's
        // bytes and the authority fold as they were (Sol review F2). The
        // revoked grant is the only thing that admits the MESSAGE the answer
        // carries, so a release would leak it (SELECTOR-RELEASE-MEMBER-REACH-
        // SCOPE = A, 15 Nov 22:23).
        let relationship = EntityId::now();
        fx.vault
            .put_entity(
                &relationship,
                ENTITY_TYPE_RELATIONSHIP,
                TimeRange { start: 1, end: 1 },
                1,
                b"a relationship space",
            )
            .unwrap();
        let access = EntityId::now();
        fx.vault
            .create_access_grant(
                &access,
                &AccessGrant {
                    principal_ref: fx.grant.member_ref,
                    scope: AccessGrantScope::Messages {
                        space_ref: relationship,
                    },
                    capability: AccessGrantCapability::MessagesRead,
                    authority_scope: Scope::top(),
                    status: AccessGrantStatus::Active,
                    created_at: 1,
                    revoked_at: None,
                    expires_at: None,
                    companion_bounds: None,
                },
            )
            .unwrap();
        let at = fx.window.start_timestamp().unwrap() + 86_400;
        let room = EntityId::now();
        let turn = EntityId::now();
        fx.vault
            .memory(fx.grant.member_ref, EdgeActorClass::Human)
            .witness(&WitnessTurn {
                conversation_ref: room.to_hex(),
                turn_ref: Some(turn.to_hex()),
                thread_audience: None,
                messages: vec![WitnessMessage {
                    id: None,
                    author: WitnessAuthor::User,
                    message_type: "dialogue".to_owned(),
                    content: "harbor view table for two".to_owned(),
                    parts: None,
                    metadata: Some(json!({"rel": relationship.to_hex()})),
                    is_visible: true,
                    order: 0,
                    quote: None,
                }],
                occurred_at: at,
                assertions: Default::default(),
            })
            .unwrap();
        let doc = create_window_doc("home", &fx.window);
        reverse_rematerialize(&fx.vault, &doc, &fx.window).unwrap();
        persist_window_snapshot(&fx.vault, &fx.window, &doc).unwrap();
        let selector = SyncSelector::new(
            fx.grant_id,
            fx.grant.member_ref,
            SyncSelectorWorld::All,
            vec![],
            vec![],
        );
        let vault = Arc::clone(&fx.vault);
        let grant = fx.grant_id;
        arm(grant, move || {
            vault
                .revoke_access_grant(&access, vault.now_recorded_at())
                .unwrap();
        });
        assert!(armed(&grant), "the hook is armed before the fetch");
        let mut socket = bound(&fx, transport::PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::SELECTOR_VV_REQUEST,
            &encode_selector_vv_request(&selector, &[]).unwrap(),
        )
        .await;
        assert_no_update(&mut socket, &fx.window).await;
        assert!(!armed(&grant), "the hook ran as the answer was queued");
    });
}

/// The embedded owner's proof, as an owner's own verb carries it.
fn owner_proof(fx: &Fixture) -> AuthenticatedOwner {
    fx.vault
        .install_device_keystore(Arc::new(MemoryKeystore::new()));
    let owner = fx.vault.ensure_embedded_owner_actor().unwrap();
    fx.vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .unwrap()
}

/// A coreference release case's vault (SELECTOR-RELEASE-COREFERENCE-CONSENT
/// = A, 15 Nov 22:23): two people joined by a Confirmed `same_as` link, the
/// grant bound to an Active pact, the owner's consent to share the link into
/// that pact, and the window persisted with all of them.
struct CoreferenceFixture {
    fx: Fixture,
    person_a: EntityId,
    person_b: EntityId,
    consent: EntityId,
    /// Every facet: the people and their link are in none.
    selector: SyncSelector,
}

async fn coreference_fixture() -> CoreferenceFixture {
    let fx = fixture().await;
    let at = fx.window.start_timestamp().unwrap() + 86_400;
    let occurred = TimeRange { start: at, end: at };
    let person_a = EntityId::now();
    let person_b = EntityId::now();
    for (id, name) in [(person_a, "ana"), (person_b, "bea")] {
        fx.vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                occurred,
                at,
                &rmp_serde::to_vec_named(&json!({"name": name})).unwrap(),
            )
            .unwrap();
    }
    let actor = WriteActor::new(person_a, EdgeActorClass::Human);
    put_coreference_link(
        &fx.vault,
        &actor,
        person_a,
        person_b,
        CoreferenceStatus::Confirmed,
        occurred,
        at,
    )
    .unwrap();
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).unwrap();
    let pact = bind_active_pact_to_grant(&fx.vault, &issuer, fx.grant_id).unwrap();
    let consent =
        coreference_share_consent(&fx.vault, &actor, person_a, person_b, &pact, occurred, at)
            .unwrap();
    let doc = create_window_doc("home", &fx.window);
    reverse_rematerialize(&fx.vault, &doc, &fx.window).unwrap();
    persist_window_snapshot(&fx.vault, &fx.window, &doc).unwrap();
    let selector = SyncSelector::new(
        fx.grant_id,
        fx.grant.member_ref,
        SyncSelectorWorld::All,
        vec![],
        vec![],
    );
    CoreferenceFixture {
        fx,
        person_a,
        person_b,
        consent,
        selector,
    }
}

/// Whether `update`, imported whole into an empty window doc, carries a
/// `same_as` edge between `a` and `b`, in either orientation.
fn carries_link(window: &WindowKey, update: &[u8], a: EntityId, b: EntityId) -> bool {
    let receiver = create_window_doc("receiver", window);
    assert!(
        receiver.import(update).unwrap().pending.is_none(),
        "the UPDATE imports whole"
    );
    let (a, b) = (a.to_hex(), b.to_hex());
    let joins = |key: &str| {
        (key.starts_with(a.as_str()) && key.ends_with(b.as_str()))
            || (key.starts_with(b.as_str()) && key.ends_with(a.as_str()))
    };
    let deep = receiver.get_deep_value();
    deep.as_map()
        .and_then(|root| root.get("edges"))
        .and_then(|edges| edges.as_map())
        .is_some_and(|edges| edges.keys().any(|key| joins(key.as_str())))
}

/// A selector answer carrying a link shared into the grant's pact leaves while the consent stands.
#[test]
fn a_selector_answer_carrying_a_consented_coreference_link_leaves() {
    run_on_engine_stack("selector-release-coreference-guard", || async {
        let case = coreference_fixture().await;
        let fx = &case.fx;
        let mut socket = bound(fx, transport::PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::SELECTOR_VV_REQUEST,
            &encode_selector_vv_request(&case.selector, &[]).unwrap(),
        )
        .await;
        let update = wait_update(&mut socket, &fx.window).await;
        assert!(
            carries_link(&fx.window, &update, case.person_a, case.person_b),
            "the standing consent's UPDATE carries the same_as link"
        );
        let mut residence = bound(fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        let index = rpc(
            &mut residence,
            2,
            "residence.index",
            json!({
                "window": fx.window.as_str(),
                "selector": encoded_selector(&case.selector),
                "limit": 16
            }),
        )
        .await;
        assert!(index["items"].is_array(), "{index}");
    });
}

/// A selector UPDATE carrying a coreference link its owner unlinks after it is made never leaves.
#[test]
fn a_selector_update_carrying_a_coreference_link_its_owner_unlinks_never_leaves() {
    run_on_engine_stack("selector-release-coreference-unlink", || async {
        let case = coreference_fixture().await;
        let fx = &case.fx;
        let owner = owner_proof(fx);
        let vault = Arc::clone(&fx.vault);
        let grant = fx.grant_id;
        let (person_a, person_b) = (case.person_a, case.person_b);
        arm(grant, move || {
            unlink_coreference_link(&vault, &owner, person_a, person_b).unwrap();
        });
        assert!(armed(&grant), "the hook is armed before the fetch");
        let mut socket = bound(fx, transport::PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::SELECTOR_VV_REQUEST,
            &encode_selector_vv_request(&case.selector, &[]).unwrap(),
        )
        .await;
        assert_no_update(&mut socket, &fx.window).await;
        assert!(!armed(&grant), "the hook ran as the answer was queued");
    });
}

/// A selector UPDATE carrying a link whose share consent is retracted after it is made never leaves.
#[test]
fn a_selector_update_carrying_a_coreference_link_whose_share_consent_is_retracted_never_leaves() {
    run_on_engine_stack("selector-release-coreference-retract", || async {
        let case = coreference_fixture().await;
        let fx = &case.fx;
        let vault = Arc::clone(&fx.vault);
        let grant = fx.grant_id;
        let consent = case.consent;
        arm(grant, move || {
            vault
                .retract_claim(&consent, vault.now_recorded_at())
                .unwrap();
        });
        assert!(armed(&grant), "the hook is armed before the fetch");
        let mut socket = bound(fx, transport::PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::SELECTOR_VV_REQUEST,
            &encode_selector_vv_request(&case.selector, &[]).unwrap(),
        )
        .await;
        assert_no_update(&mut socket, &fx.window).await;
        assert!(!armed(&grant), "the hook ran as the answer was queued");
    });
}

/// A residence index carrying a coreference link its owner unlinks after it is made is refused.
#[test]
fn a_residence_index_carrying_a_coreference_link_its_owner_unlinks_is_refused() {
    run_on_engine_stack("selector-release-coreference-index", || async {
        let case = coreference_fixture().await;
        let fx = &case.fx;
        let owner = owner_proof(fx);
        let vault = Arc::clone(&fx.vault);
        let grant = fx.grant_id;
        let (person_a, person_b) = (case.person_a, case.person_b);
        arm(grant, move || {
            unlink_coreference_link(&vault, &owner, person_a, person_b).unwrap();
        });
        assert!(armed(&grant), "the hook is armed before the call");
        let mut socket = bound(fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        send_rpc(
            &mut socket,
            2,
            "residence.index",
            json!({
                "window": fx.window.as_str(),
                "selector": encoded_selector(&case.selector),
                "limit": 16
            }),
        )
        .await;
        let error = rpc_reply_within(&mut socket, 2, REPLY_WAIT)
            .await
            .expect_err("a reply queued before its link was unlinked is refused, never a result");
        assert_eq!(error["code"], "RESULT_CHANGED", "{error}");
        assert!(!armed(&grant), "the hook ran as the answer was queued");
    });
}
