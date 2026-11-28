//! Socket regressions for the shared-vault member lane, using base-public APIs only.
//! The lane header and RPC names are wire strings, not server internals.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use futures_util::{SinkExt, StreamExt};
use loro::{ExportMode, LoroDoc, VersionVector};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::claim::{ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope, ScopeAxis,
    ScopeId, SharedVaultPreset,
};
use oneiron::registry::{
    ENTITY_TYPE_CLAIM, ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON, ENTITY_TYPE_WORLD,
};
use oneiron::store::GateDecisionId;
use oneiron::sync::schema::create_window_doc;
use oneiron::sync::server_state::{persist_window_snapshot, window_snapshot_present};
use oneiron::sync::transport::{self, window_sub_tags};
use oneiron::sync::window::{load_window_from_state, reverse_rematerialize};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, encode_selector_vv_request, encode_sync_selector,
    put_selector_test_federation_grant,
};
use oneiron::write_envelope::claim_body::encode_claim_body;
use oneiron::{DeleteReason, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_contracts::record_layout::ENTITY_METADATA_HEADER_LEN;
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{
    ENGINE_THREAD_STACK_BYTES, build_app, config::SyncServerConfig, server::SyncServer,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{Error as WsError, Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
const REPLY_WAIT: Duration = Duration::from_secs(10);
// A catalogue page over 261 world windows opens and judges each one; in a
// debug build on a loaded test host that takes seconds, not milliseconds.
const CATALOGUE_WAIT: Duration = Duration::from_secs(120);
const ROOT_OBSERVATION: Duration = Duration::from_millis(250);
// Ten of a socket's body upkeep polls (asset_bodies::ASSET_BODY_POLL, 50 ms).
#[cfg(all(oneiron_test_support, feature = "mesh"))]
const BODY_UPKEEP_OBSERVATION: Duration = Duration::from_millis(500);
// dispatch_error maps InvalidPayload to DECODE_ERROR, not UNKNOWN_TAG.
const REFUSED_FRAME: u16 = 4002;
// transport::close_revoked uses CLOSE_RPC_NO_PRINCIPAL on the owner path too.
const REVOKED_CREDENTIAL: u16 = 4008;

fn run_on_engine_stack<F, Fut>(test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .unwrap()
                .block_on(test());
        })
        .unwrap();
    if let Err(panic) = driver.join() {
        std::panic::resume_unwind(panic);
    }
}

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
    fn binding(&self, vault: &Vault) -> Value {
        let timestamp = vault.now_recorded_at();
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

    fn bind_params(&self, vault: &Vault) -> Value {
        json!({"token": self.slip.to_token().unwrap(), "binding": self.binding(vault)})
    }
}

#[derive(Clone, Copy)]
enum WindowFixture {
    Selected,
    Mixed,
    PortableWorld,
}

#[derive(Default)]
struct FixtureOptions {
    empty_world_windows: usize,
    bound_grant_to_world: bool,
}

struct Fixture {
    task: tokio::task::JoinHandle<()>,
    url: String,
    vault: Arc<Vault>,
    /// The home's own window manager (the one its body upkeep opens windows
    /// in), for a test that asks which windows it has open.
    #[cfg(all(oneiron_test_support, feature = "mesh"))]
    home_windows: Arc<oneiron::sync::WindowManager>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
    member: EntityId,
    grant_id: EntityId,
    grant: FederationGrant,
    caller: Caller,
    selector: SyncSelector,
    window: WindowKey,
    other_window: WindowKey,
    item: EntityId,
    other_item: EntityId,
    world: Option<EntityId>,
    _dir: tempfile::TempDir,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn mint(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    root: &CapabilitySlip,
    holder: EntityId,
    grant: Option<(EntityId, &FederationGrant)>,
    class: &str,
    records: BTreeSet<String>,
) -> Caller {
    let key = SigningKey::from_bytes(blake3::hash(EntityId::now().as_bytes()).as_bytes());
    let mut claims = root.claims.clone();
    claims.slip_id = *blake3::hash(EntityId::now().as_bytes()).as_bytes();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.org_ref = None;
    claims.binding_key = key.verifying_key().to_bytes();
    claims.single_use = false;
    claims.records = records;
    claims.channels.clear();
    claims.grant_ref = grant.map(|(id, _)| id.to_hex());
    if let Some((_, grant)) = grant {
        claims.scope = grant.authority_scope.clone();
    }
    Caller {
        slip: vault.mint_capability_slip(issuer, claims).unwrap(),
        key,
    }
}

fn public_world_claim(subject: EntityId, world: EntityId, value: &str) -> ClaimBody {
    let mut claim = ClaimBody::new(
        "member_sync.fixture",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(value),
        0.8,
        // A residence index reads only surfaceable claims (Auto or Approved).
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .unwrap();
    claim.world = Some(world);
    claim.scope = Some(rmpv::Value::Map(vec![(
        rmpv::Value::from("sensitivity"),
        rmpv::Value::from("public"),
    )]));
    claim
}

async fn fixture(shape: WindowFixture) -> Fixture {
    fixture_with_options(shape, FixtureOptions::default()).await
}

async fn fixture_with_options(shape: WindowFixture, options: FixtureOptions) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).unwrap());
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().unwrap();
    let issuer = vault.bootstrap_host_slip_issuer().unwrap();
    let root = vault.ensure_host_root_slip(&issuer).unwrap();
    vault.provision_engine_machine_identities(&issuer).unwrap();
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .unwrap();
    let owner = vault.ensure_embedded_owner_actor().unwrap();
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .unwrap();
    // Initialization grants only the creator. It must precede the member row.
    vault
        .initialize_shared_vault(
            &proof,
            42,
            Some(SharedVaultPreset::Team),
            &[],
            vault.now_recorded_at(),
        )
        .unwrap();
    let member = person(&vault, "yuki");
    let world = matches!(shape, WindowFixture::PortableWorld).then(EntityId::now);
    if let Some(world) = world {
        vault
            .put_entity(
                &world,
                ENTITY_TYPE_WORLD,
                TimeRange { start: 1, end: 1 },
                1,
                &rmp_serde::to_vec_named(&json!({"title": "Portable world"})).unwrap(),
            )
            .unwrap();
    }
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        FederationGrantScope::vault(42),
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    if options.bound_grant_to_world {
        grant.authority_scope.worlds = ScopeAxis::Some(BTreeSet::from([ScopeId(
            world.expect("world-bounded fixture"),
        )]));
    }
    put_selector_test_federation_grant(&vault, &grant_id, &grant, vault.now_recorded_at()).unwrap();
    let caller = mint(
        &vault,
        &issuer,
        &root,
        member,
        Some((grant_id, &grant)),
        "human",
        BTreeSet::new(),
    );

    let month = WindowKey::try_new("2026-03").unwrap();
    let other_window = WindowKey::try_new("2026-04").unwrap();
    let at = month.start_timestamp().unwrap() + 86_400;
    let other_at = other_window.start_timestamp().unwrap() + 86_400;
    let item = EntityId::now();
    let other_item = EntityId::now();
    let window = world.map_or_else(|| month.clone(), |id| WindowKey::for_world(at, id));
    if let Some(world) = world {
        let claim = public_world_claim(member, world, "before");
        vault
            .put_entity(
                &item,
                ENTITY_TYPE_CLAIM,
                TimeRange { start: at, end: at },
                at,
                &encode_claim_body(&claim).unwrap(),
            )
            .unwrap();
        // The public helper uses this vault's actual keystore issuer, not the test default.
        vault
            .keep_world_on_this_machine_under_for_test(&issuer, world, false)
            .unwrap();
    } else {
        vault
            .put_entity(
                &item,
                ENTITY_TYPE_FACET,
                TimeRange { start: at, end: at },
                at,
                &rmp_serde::to_vec_named(&json!({"title": "Selected facet"})).unwrap(),
            )
            .unwrap();
    }
    let hidden_at = if matches!(shape, WindowFixture::Mixed) {
        at
    } else {
        other_at
    };
    vault
        .put_entity(
            &other_item,
            ENTITY_TYPE_FACET,
            TimeRange {
                start: hidden_at,
                end: hidden_at,
            },
            hidden_at,
            &rmp_serde::to_vec_named(&json!({"title": "Other facet"})).unwrap(),
        )
        .unwrap();
    for key in [&window, &other_window] {
        let doc = create_window_doc("home", key);
        reverse_rematerialize(&vault, &doc, key).unwrap();
        persist_window_snapshot(&vault, key, &doc).unwrap();
    }
    for _ in 0..options.empty_world_windows {
        let key = WindowKey::for_world(at, EntityId::now());
        let doc = create_window_doc("home", &key);
        assert_eq!(reverse_rematerialize(&vault, &doc, &key).unwrap(), 0);
        persist_window_snapshot(&vault, &key, &doc).unwrap();
    }
    let selector = SyncSelector::new(
        grant_id,
        member,
        SyncSelectorWorld::All,
        if world.is_some() { vec![] } else { vec![item] },
        vec![],
    );
    // Startup discovers the persisted windows; no pub(crate) server root/window door is used.
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("member-sync-socket".into()),
                ..Default::default()
            },
        )
        .unwrap(),
    );
    #[cfg(all(oneiron_test_support, feature = "mesh"))]
    let home_windows = oneiron_server::test_doors::embedded_peer_path::device_link_windows(&server);
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
        #[cfg(all(oneiron_test_support, feature = "mesh"))]
        home_windows,
        issuer,
        root,
        owner,
        member,
        grant_id,
        grant,
        caller,
        selector,
        window,
        other_window,
        item,
        other_item,
        world,
        _dir: dir,
    }
}

fn encoded_selector(selector: &SyncSelector) -> String {
    base64::engine::general_purpose::STANDARD.encode(encode_sync_selector(selector).unwrap())
}

async fn upgrade(fx: &Fixture, caller: &Caller, member_lane: bool) -> Result<Socket, WsError> {
    let mut request = fx.url.as_str().into_client_request().unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {}", caller.slip.to_token().unwrap())
            .parse()
            .unwrap(),
    );
    request.headers_mut().insert(
        "x-oneiron-binding",
        caller.binding(&fx.vault).to_string().parse().unwrap(),
    );
    if member_lane {
        request
            .headers_mut()
            .insert("oneiron-sync-lane", "member".parse().unwrap());
    }
    let (socket, response) =
        tokio::time::timeout(REPLY_WAIT, tokio_tungstenite::connect_async(request))
            .await
            .expect("upgrade deadline")?;
    assert_eq!(response.status().as_u16(), 101);
    Ok(socket)
}

async fn expect_status(fx: &Fixture, caller: &Caller, expected: u16) {
    match upgrade(fx, caller, true).await {
        Err(WsError::Http(response)) => assert_eq!(response.status().as_u16(), expected),
        Err(error) => panic!("expected HTTP {expected}, got {error:?}"),
        Ok(_) => panic!("expected HTTP {expected}, got a socket"),
    }
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

async fn next_member_binary(socket: &mut Socket) -> Vec<u8> {
    next_member_binary_within(socket, REPLY_WAIT).await
}

async fn next_member_binary_within(socket: &mut Socket, wait: Duration) -> Vec<u8> {
    loop {
        match next_message_within(socket, wait).await {
            Message::Binary(data) => {
                assert!(
                    !matches!(data.first().copied(), Some(0 | 6)),
                    "a member received a root frame"
                );
                return data.to_vec();
            }
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("expected a member reply, got {other:?}"),
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

async fn rpc_reply(socket: &mut Socket, id: u64) -> Result<Value, Value> {
    rpc_reply_within(socket, id, REPLY_WAIT).await
}

async fn rpc_reply_within(socket: &mut Socket, id: u64, wait: Duration) -> Result<Value, Value> {
    let mut bytes = Vec::new();
    let mut seq = 0;
    loop {
        let frame = next_member_binary_within(socket, wait).await;
        assert_eq!(frame[0], transport::TAG_RPC, "unexpected frame: {frame:?}");
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
    rpc_within(socket, id, method, params, REPLY_WAIT).await
}

async fn rpc_within(
    socket: &mut Socket,
    id: u64,
    method: &str,
    params: Value,
    wait: Duration,
) -> Value {
    send_rpc(socket, id, method, params).await;
    rpc_reply_within(socket, id, wait)
        .await
        .unwrap_or_else(|error| panic!("{method} refused: {error}"))
}

async fn bound_member(fx: &Fixture, version: u8) -> Socket {
    let mut socket = upgrade(fx, &fx.caller, true)
        .await
        .expect("member upgrade is 101");
    // Minimal hello lists no codecs, so the assertions inspect unwrapped tags.
    send_binary(&mut socket, vec![transport::TAG_PROTOCOL_HELLO, version]).await;
    let result = rpc(
        &mut socket,
        1,
        "auth.bind",
        fx.caller.bind_params(&fx.vault),
    )
    .await;
    assert_eq!(
        result,
        Value::Null,
        "same-slip bind has a terminal success reply"
    );
    socket
}

async fn expect_close(socket: &mut Socket, code: u16) {
    loop {
        match next_message(socket).await {
            Message::Close(Some(close)) => {
                assert_eq!(u16::from(close.code), code);
                return;
            }
            Message::Ping(_) | Message::Pong(_) => {}
            other => panic!("expected close {code} without an application answer, got {other:?}"),
        }
    }
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

fn durable_rows(fx: &Fixture) -> Vec<Option<Vec<u8>>> {
    [fx.item, fx.other_item, fx.grant_id]
        .into_iter()
        .map(|id| fx.vault.get_raw(&id).unwrap())
        .collect()
}

#[test]
fn a_member_socket_serves_its_grant_and_no_root_frame() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let selector = encoded_selector(&fx.selector);
        let catalogue = rpc(
            &mut socket,
            2,
            "residence.windows",
            json!({
                "selector": selector, "months": ["2026-03"], "limit": 16
            }),
        )
        .await;
        assert_eq!(catalogue["windows"], json!([fx.window.as_str()]));
        assert!(catalogue["next"].is_null());
        let index = rpc(
            &mut socket,
            3,
            "residence.index",
            json!({
                "window": fx.window.as_str(), "selector": selector, "limit": 16
            }),
        )
        .await;
        assert_eq!(index["items"].as_array().unwrap().len(), 1);
        assert_eq!(index["items"][0]["entity_id"], fx.item.to_hex());
        // Absence is checked only after explicit bind/catalogue/index replies.
        // A close, EOF or unrelated binary is a failure, not quiet success.
        let observation = tokio::time::timeout(ROOT_OBSERVATION, async {
            loop {
                match next_message(&mut socket).await {
                    Message::Ping(_) | Message::Pong(_) => {}
                    frame => panic!("unsolicited frame after bind/index: {frame:?}"),
                }
            }
        })
        .await;
        assert!(
            observation.is_err(),
            "the bounded observation must complete"
        );
        let after = rpc(
            &mut socket,
            4,
            "residence.index",
            json!({
                "window": fx.window.as_str(), "selector": selector, "limit": 16
            }),
        )
        .await;
        assert_eq!(
            after["items"], index["items"],
            "the socket is still live after observation"
        );
        assert_eq!(durable_rows(&fx), before);
    });
}

/// The `UPDATE` a member's selector fetch of `window` is answered with,
/// imported into a fresh doc.
async fn member_fetch_answer(fx: &Fixture, window: &WindowKey) -> LoroDoc {
    let mut socket = bound_member(fx, transport::PROTOCOL_VERSION).await;
    member_fetch_answer_on(&mut socket, window, &fx.selector).await
}

/// [`member_fetch_answer`] on the bound member `socket`, under `selector`.
async fn member_fetch_answer_on(
    socket: &mut Socket,
    window: &WindowKey,
    selector: &SyncSelector,
) -> LoroDoc {
    send_window(
        socket,
        window,
        window_sub_tags::SELECTOR_VV_REQUEST,
        &encode_selector_vv_request(selector, &[]).unwrap(),
    )
    .await;
    let answer = next_member_binary(socket).await;
    assert_eq!(answer[0], transport::TAG_WINDOW_SYNC);
    let (key, tag, update) = transport::decode_window_sync(&answer[1..]).unwrap();
    assert_eq!(key, window.as_str());
    assert_eq!(tag, window_sub_tags::UPDATE);
    let served = LoroDoc::new();
    served.import(update).unwrap();
    served
}

/// Whether the root the home persisted lists `window`.
fn persisted_root_lists(vault: &Vault, window: &WindowKey) -> bool {
    oneiron::sync::server_state::load_root_from_state(vault)
        .unwrap()
        .is_some_and(|root| oneiron::sync::schema::read_window_list(&root).contains(window))
}

/// WINDOW-FETCH-CREATES-NAMED-WINDOW (SYNC-RECEIVE-READ-20261127 F9;
/// WINDOW-FETCH-NO-CREATE = yes, Engine 27 Nov 16:43): a member's selector
/// fetch of a window the root does not list is answered as an empty window
/// and creates nothing: no `d:w:*` snapshot, and no persisted root that lists
/// it.
/// red with the fetch served through `serve_window` again: the fetch
/// snapshots the window and persists a root that lists it.
#[test]
fn a_member_fetch_of_an_unlisted_window_is_answered_empty_and_creates_nothing() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let unlisted = WindowKey::try_new("2019-07").unwrap();
        assert!(!window_snapshot_present(&fx.vault, &unlisted).unwrap());
        assert!(!persisted_root_lists(&fx.vault, &unlisted));
        let served = member_fetch_answer(&fx, &unlisted).await;
        assert!(
            served.get_map("entities").is_empty(),
            "the unlisted window is answered empty"
        );
        assert!(
            !window_snapshot_present(&fx.vault, &unlisted).unwrap(),
            "the fetch snapshotted no window"
        );
        assert!(
            !persisted_root_lists(&fx.vault, &unlisted),
            "the fetch persisted no root that lists the window"
        );
    });
}

/// The same change leaves a listed window's fetch as it was: a member's
/// selector fetch of the window the root lists is still answered with its
/// selected row.
#[test]
fn a_member_fetch_of_a_listed_window_still_serves_its_selected_row() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let served = member_fetch_answer(&fx, &fx.window).await;
        assert!(
            !served.get_map("entities").is_empty(),
            "the listed window's answer carries its selected row"
        );
    });
}

/// REVIEW-10604 P1 2: a member's selector fetch of a month the root does not
/// list is answered empty even when the vault stores a row in that month that
/// the member's selector selects. The row is stored after the home started,
/// so its boot reconcile did not list the month, and nothing served the
/// month since. The answer is the empty window as it is, not the selector
/// filter's copy, which packs the rows the vault stores under the key.
/// red with the unlisted answer made through the selector filter again (head
/// 5cc797cf): the answer carries the stored row.
#[test]
fn a_member_fetch_of_an_unlisted_month_with_a_stored_selected_row_is_answered_empty() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let unlisted = WindowKey::try_new("2019-07").unwrap();
        let stored = EntityId::now();
        let stored_at = unlisted.start_timestamp().unwrap() + 86_400;
        fx.vault
            .put_entity(
                &stored,
                ENTITY_TYPE_FACET,
                TimeRange {
                    start: stored_at,
                    end: stored_at,
                },
                stored_at,
                &rmp_serde::to_vec_named(&json!({"title": "Stored facet"})).unwrap(),
            )
            .unwrap();
        assert!(!persisted_root_lists(&fx.vault, &unlisted));
        let selector = SyncSelector::new(
            fx.grant_id,
            fx.member,
            SyncSelectorWorld::All,
            vec![stored],
            vec![],
        );
        let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let served = member_fetch_answer_on(&mut socket, &unlisted, &selector).await;
        assert!(
            served.get_map("entities").is_empty(),
            "the unlisted month is answered empty, without its stored row"
        );
        assert!(
            !window_snapshot_present(&fx.vault, &unlisted).unwrap(),
            "the fetch snapshotted no window"
        );
        assert!(
            !persisted_root_lists(&fx.vault, &unlisted),
            "the fetch persisted no root that lists the window"
        );
    });
}

/// REVIEW-10604 P1 1: an unlisted window's empty answer is not kept as one of
/// the socket's admitted copies, so the socket's body upkeep, which rebuilds
/// each kept copy from the home's window on every poll, opens no window for
/// the key while the socket stays open.
/// red with the empty answer kept as an admitted copy again (head 5cc797cf):
/// the upkeep's rebuild opens the unlisted window in the home's manager.
#[cfg(all(oneiron_test_support, feature = "mesh"))]
#[test]
fn a_member_fetch_of_an_unlisted_window_leaves_no_window_for_the_body_upkeep_to_open() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let unlisted = WindowKey::try_new("2019-07").unwrap();
        let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let served = member_fetch_answer_on(&mut socket, &unlisted, &fx.selector).await;
        assert!(
            served.get_map("entities").is_empty(),
            "the unlisted window is answered empty"
        );
        // The socket stays open across several body upkeep polls.
        let observation = tokio::time::timeout(BODY_UPKEEP_OBSERVATION, async {
            loop {
                if let Message::Close(close) = next_message(&mut socket).await {
                    panic!("the socket closed during the observation: {close:?}");
                }
            }
        })
        .await;
        assert!(
            observation.is_err(),
            "the bounded observation must complete"
        );
        assert!(
            fx.home_windows.window(&unlisted).is_none(),
            "the body upkeep opened no window for the unlisted key"
        );
        assert!(
            !window_snapshot_present(&fx.vault, &unlisted).unwrap(),
            "nothing snapshotted the unlisted window"
        );
    });
}

#[test]
fn a_member_socket_refuses_full_window_and_a_foreign_selector() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        let unseen = WindowKey::try_new("2026-02").unwrap();
        assert!(!window_snapshot_present(&fx.vault, &unseen).unwrap());
        let mut raw = bound_member(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        send_window(
            &mut raw,
            &unseen,
            window_sub_tags::VV_REQUEST,
            &VersionVector::default().encode(),
        )
        .await;
        expect_close(&mut raw, REFUSED_FRAME).await;
        assert!(
            !window_snapshot_present(&fx.vault, &unseen).unwrap(),
            "refused VV creates no window"
        );

        let second_id = EntityId::now();
        put_selector_test_federation_grant(
            &fx.vault,
            &second_id,
            &fx.grant,
            fx.vault.now_recorded_at(),
        )
        .unwrap();
        let other_holder = person(&fx.vault, "owen");
        let other_id = EntityId::now();
        let other = FederationGrant::new(
            FederationGrantScope::vault(42),
            other_holder,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        );
        put_selector_test_federation_grant(
            &fx.vault,
            &other_id,
            &other,
            fx.vault.now_recorded_at(),
        )
        .unwrap();
        for (grant, holder) in [(second_id, fx.member), (other_id, other_holder)] {
            let selector = SyncSelector::new(grant, holder, SyncSelectorWorld::All, vec![], vec![]);
            for promotion in [true, false] {
                let mut socket = bound_member(
                    &fx,
                    if promotion {
                        transport::RESIDENCE_PROTOCOL_VERSION
                    } else {
                        transport::PROTOCOL_VERSION
                    },
                )
                .await;
                let (tag, payload) = if promotion {
                    (
                        window_sub_tags::PROMOTION_REQUEST,
                        encode_sync_selector(&selector).unwrap(),
                    )
                } else {
                    (
                        window_sub_tags::SELECTOR_VV_REQUEST,
                        encode_selector_vv_request(&selector, &[]).unwrap(),
                    )
                };
                send_window(&mut socket, &fx.window, tag, &payload).await;
                expect_close(&mut socket, REFUSED_FRAME).await;
            }
        }
        assert_eq!(durable_rows(&fx), before);
    });
}

#[test]
fn a_member_upgrade_with_a_dead_or_foreign_grant_gets_no_socket() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        // A live member of a different shared vault: member standing refuses 403.
        let foreign_id = EntityId::now();
        let foreign = FederationGrant::new(
            FederationGrantScope::vault(43),
            fx.member,
            FederationGrantRole::Member,
            FederationGrantPreset::Member,
        );
        put_selector_test_federation_grant(
            &fx.vault,
            &foreign_id,
            &foreign,
            fx.vault.now_recorded_at(),
        )
        .unwrap();
        let foreign_caller = mint(
            &fx.vault,
            &fx.issuer,
            &fx.root,
            fx.member,
            Some((foreign_id, &foreign)),
            "human",
            BTreeSet::new(),
        );
        expect_status(&fx, &foreign_caller, 403).await;
        // Another holder's grant fails require_live_slip_grant at the binding door: 401,
        // before the member lane's 403. It is not a live credential of this holder.
        let mismatched = mint(
            &fx.vault,
            &fx.issuer,
            &fx.root,
            person(&fx.vault, "owen"),
            Some((fx.grant_id, &fx.grant)),
            "human",
            BTreeSet::new(),
        );
        expect_status(&fx, &mismatched, 401).await;
        // A live Ask guest has a real disclosure caveat, but is no shared member: 403.
        let guest_id = EntityId::now();
        let guest = FederationGrant::ask_guest(
            EntityId::now(),
            fx.member,
            fx.member,
            fx.owner,
            BTreeSet::from([fx.item]),
        )
        .unwrap();
        put_selector_test_federation_grant(
            &fx.vault,
            &guest_id,
            &guest,
            fx.vault.now_recorded_at(),
        )
        .unwrap();
        let guest_caller = mint(
            &fx.vault,
            &fx.issuer,
            &fx.root,
            fx.member,
            Some((guest_id, &guest)),
            "human",
            BTreeSet::from([fx.item.to_hex()]),
        );
        expect_status(&fx, &guest_caller, 403).await;
        // This non-human presentation still holds a live PERSON-backed grant;
        // actor_class, independently of grant liveness, makes the member door refuse 403.
        let non_human = mint(
            &fx.vault,
            &fx.issuer,
            &fx.root,
            fx.member,
            Some((fx.grant_id, &fx.grant)),
            "agent",
            BTreeSet::new(),
        );
        expect_status(&fx, &non_human, 403).await;
        assert_eq!(durable_rows(&fx), before);
        // Deletion invalidates the credential at the binding door: exactly 401.
        fx.vault.delete_entity(&fx.grant_id).unwrap();
        assert!(fx.vault.is_deleted_shell(&fx.grant_id).unwrap());
        expect_status(&fx, &fx.caller, 401).await;
        assert_eq!(fx.vault.get_raw(&fx.item).unwrap(), before[0]);
    });
}

#[test]
fn the_narrow_member_slip_without_the_header_keeps_its_facade_socket_guard() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        let mut socket = upgrade(&fx, &fx.caller, false)
            .await
            .expect("facade upgrade is 101");
        send_binary(
            &mut socket,
            vec![transport::TAG_PROTOCOL_HELLO, transport::PROTOCOL_VERSION],
        )
        .await;
        assert_eq!(
            rpc(
                &mut socket,
                1,
                "auth.bind",
                fx.caller.bind_params(&fx.vault)
            )
            .await,
            Value::Null
        );
        send_binary(
            &mut socket,
            transport::encode_window_sync(
                fx.window.as_str(),
                window_sub_tags::VV_REQUEST,
                &VersionVector::default().encode(),
            )
            .into_result()
            .unwrap(),
        )
        .await;
        // Facade sockets still refuse sync tags as UNKNOWN_TAG, not the member lane's 4002.
        expect_close(&mut socket, 4003).await;
        assert_eq!(durable_rows(&fx), before);
    });
}

#[test]
fn a_member_socket_closes_when_its_grant_is_deleted() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = fx.vault.get_raw(&fx.item).unwrap();
        let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let readable = rpc(&mut socket, 2, "residence.index", json!({
            "window": fx.window.as_str(), "selector": encoded_selector(&fx.selector), "limit": 16
        })).await;
        assert_eq!(readable["items"][0]["entity_id"], fx.item.to_hex());
        fx.vault.delete_entity(&fx.grant_id).unwrap();
        assert!(fx.vault.is_deleted_shell(&fx.grant_id).unwrap());
        send_rpc(&mut socket, 2, "ping", json!({"after": "grant deletion"})).await;
        expect_close(&mut socket, REVOKED_CREDENTIAL).await;
        assert_eq!(fx.vault.get_raw(&fx.item).unwrap(), before);
        expect_status(&fx, &fx.caller, 401).await;
    });
}

#[test]
fn a_member_socket_refuses_owner_machine_calls() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        let mut vv = vec![transport::TAG_VERSION_VECTOR];
        vv.extend_from_slice(&VersionVector::default().encode());
        for frame in [
            vv,
            transport::encode_lfs_chunk_sync(&[0])
                .into_result()
                .unwrap(),
        ] {
            let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
            send_binary(&mut socket, frame).await;
            expect_close(&mut socket, REFUSED_FRAME).await;
        }
        for method in ["residence.bundle.list", "residence.authority.tail"] {
            let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
            send_rpc(&mut socket, 2, method, json!({})).await;
            expect_close(&mut socket, REFUSED_FRAME).await;
        }
        let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        send_envelope(&mut socket, transport::TAG_SUB, "sub.close", 7, json!({})).await;
        expect_close(&mut socket, REFUSED_FRAME).await;
        assert_eq!(
            durable_rows(&fx),
            before,
            "owner-machine calls changed no fixture row"
        );
    });
}

#[test]
fn the_catalogue_lists_only_windows_the_grant_reads() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let selector = encoded_selector(&fx.selector);
        let catalogue = rpc(
            &mut socket,
            2,
            "residence.windows",
            json!({
                "selector": selector, "months": ["2026-03", "2026-04"], "limit": 16
            }),
        )
        .await;
        assert_eq!(catalogue["windows"], json!([fx.window.as_str()]));
        assert!(catalogue["next"].is_null());
        let hidden = rpc(
            &mut socket,
            3,
            "residence.index",
            json!({
                "window": fx.other_window.as_str(), "selector": selector, "limit": 16
            }),
        )
        .await;
        assert_eq!(hidden["items"], json!([]));
        let visible = rpc(
            &mut socket,
            4,
            "residence.index",
            json!({
                "window": fx.window.as_str(), "selector": selector, "limit": 16
            }),
        )
        .await;
        assert_eq!(visible["items"][0]["entity_id"], fx.item.to_hex());
        // The excluded window is not empty: a widening of this caller's selector reads it.
        let wide = SyncSelector::new(
            fx.grant_id,
            fx.member,
            SyncSelectorWorld::All,
            vec![],
            vec![],
        );
        let control = rpc(
            &mut socket,
            5,
            "residence.index",
            json!({
                "window": fx.other_window.as_str(), "selector": encoded_selector(&wide), "limit": 16
            }),
        )
        .await;
        assert!(
            control["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["entity_id"] == fx.other_item.to_hex())
        );
        assert_eq!(durable_rows(&fx), before);
    });
}

#[test]
fn the_owner_socket_still_starts_with_the_root_snapshot_guard() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        let owner = mint(
            &fx.vault,
            &fx.issuer,
            &fx.root,
            fx.owner,
            None,
            "human",
            BTreeSet::new(),
        );
        let mut socket = upgrade(&fx, &owner, false)
            .await
            .expect("owner device upgrade is 101");
        send_binary(
            &mut socket,
            vec![transport::TAG_PROTOCOL_HELLO, transport::PROTOCOL_VERSION],
        )
        .await;
        let Message::Binary(frame) = next_message(&mut socket).await else {
            panic!("the owner's first message must be the root snapshot");
        };
        assert_eq!(frame[0], 0);
        let root = LoroDoc::new();
        root.import(&frame[1..])
            .expect("a genuine Loro root snapshot");
        assert!(oneiron::sync::schema::read_window_list(&root).contains(&fx.window));
        assert_eq!(durable_rows(&fx), before);
    });
}

#[test]
fn a_narrowed_member_slip_gets_no_member_lane() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        let narrow = mint(
            &fx.vault,
            &fx.issuer,
            &fx.root,
            fx.member,
            Some((fx.grant_id, &fx.grant)),
            "human",
            BTreeSet::from([fx.item.to_hex()]),
        );
        expect_status(&fx, &narrow, 403).await;
        let mut whole = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let answer = rpc(&mut whole, 2, "residence.index", json!({
            "window": fx.window.as_str(), "selector": encoded_selector(&fx.selector), "limit": 16
        })).await;
        assert_eq!(answer["items"][0]["entity_id"], fx.item.to_hex());
        assert_eq!(durable_rows(&fx), before);
    });
}

/// Astra T3 on MEMBER-SYNC PR 1: the member's whole slip handed to another
/// key (`attenuate_to`, a shorter lifetime its only narrowing) still names
/// the member and the grant, but whoever proves it is not the member. It
/// opens no member lane; the member's own slip still does.
#[test]
fn a_member_slip_handed_to_another_key_gets_no_member_lane() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        let next = SigningKey::from_bytes(blake3::hash(EntityId::now().as_bytes()).as_bytes());
        let mut slip = fx.caller.slip.clone();
        slip.attenuate_to(
            oneiron::authority::SlipCaveat {
                ttl_secs: Some(3600),
                ..Default::default()
            },
            &fx.caller.key,
            next.verifying_key().to_bytes(),
        )
        .unwrap();
        let handed = Caller { slip, key: next };
        expect_status(&fx, &handed, 403).await;
        let mut own = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let answer = rpc(&mut own, 2, "residence.index", json!({
            "window": fx.window.as_str(), "selector": encoded_selector(&fx.selector), "limit": 16
        })).await;
        assert_eq!(answer["items"][0]["entity_id"], fx.item.to_hex());
        assert_eq!(durable_rows(&fx), before);
    });
}

#[test]
fn a_member_window_vv_needs_the_whole_window() {
    run_on_engine_stack(|| async {
        for shape in [WindowFixture::Mixed, WindowFixture::Selected] {
            let fx = fixture(shape).await;
            let before = durable_rows(&fx);
            let mut socket = bound_member(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
            // Both fixtures really serve the selected row before the VV is asked for.
            let index = rpc(&mut socket, 2, "residence.index", json!({
                "window": fx.window.as_str(), "selector": encoded_selector(&fx.selector), "limit": 16
            })).await;
            assert_eq!(index["items"].as_array().unwrap().len(), 1);
            assert_eq!(index["items"][0]["entity_id"], fx.item.to_hex());
            send_rpc(
                &mut socket,
                3,
                "residence.window.vv",
                json!({
                    "window": fx.window.as_str(), "selector": encoded_selector(&fx.selector)
                }),
            )
            .await;
            match shape {
                WindowFixture::Mixed => {
                    let error = rpc_reply(&mut socket, 3)
                        .await
                        .expect_err("mixed window VV is refused");
                    assert_eq!(error["code"], "NOT_FOUND");
                }
                WindowFixture::Selected => {
                    let answer = rpc_reply(&mut socket, 3)
                        .await
                        .expect("whole window VV is served");
                    assert_eq!(answer["window"], fx.window.as_str());
                    let vv = base64::engine::general_purpose::STANDARD
                        .decode(answer["vv"].as_str().unwrap())
                        .unwrap();
                    let decoded = VersionVector::decode(&vv).unwrap();
                    assert_ne!(decoded, VersionVector::default());
                }
                WindowFixture::PortableWorld => unreachable!(),
            }
            assert_eq!(durable_rows(&fx), before);
        }
    });
}

#[test]
fn a_member_residence_update_after_a_world_privacy_change_is_refused() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::PortableWorld).await;
        let world = fx.world.unwrap();
        let original = fx.vault.get_raw(&fx.item).unwrap().unwrap();
        let mut socket = bound_member(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        let index = rpc(&mut socket, 2, "residence.index", json!({
            "window": fx.window.as_str(), "selector": encoded_selector(&fx.selector), "limit": 16
        })).await;
        assert!(
            index["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["entity_id"] == fx.item.to_hex())
        );
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::PROMOTION_REQUEST,
            &encode_sync_selector(&fx.selector).unwrap(),
        )
        .await;
        let granted = next_member_binary(&mut socket).await;
        assert_eq!(granted[0], transport::TAG_WINDOW_SYNC);
        let (key, tag, payload) = transport::decode_window_sync(&granted[1..]).unwrap();
        assert_eq!(key, fx.window.as_str());
        assert_eq!(tag, window_sub_tags::PROMOTION_GRANTED);
        assert!(payload.is_empty());

        // Author a valid delta over the already-promoted canonical history, not a new row.
        let persisted = load_window_from_state(&fx.vault, "home", &fx.window).unwrap();
        let peer = persisted.fork();
        let before_edit = peer.oplog_vv();
        let changed = public_world_claim(fx.member, world, "must not land");
        let mut raw = original[..ENTITY_METADATA_HEADER_LEN].to_vec();
        raw.extend_from_slice(&encode_claim_body(&changed).unwrap());
        peer.get_map("entities")
            .insert(&fx.item.to_hex(), raw.as_slice())
            .unwrap();
        peer.commit();
        let update = peer.export(ExportMode::updates(&before_edit)).unwrap();
        assert!(!update.is_empty());

        // No machine was asserted by this socket: Everywhere admits it; home-only withholds it.
        // The grant and slip stay live, so this must exercise promotion reauthorization, not revoke.
        fx.vault
            .keep_world_on_this_machine_under_for_test(&fx.issuer, world, true)
            .unwrap();
        let hidden = rpc(&mut socket, 3, "residence.index", json!({
            "window": fx.window.as_str(), "selector": encoded_selector(&fx.selector), "limit": 16
        })).await;
        assert_eq!(
            hidden["items"],
            json!([]),
            "HOME now withholds the world from this destination"
        );
        let before_update = load_window_from_state(&fx.vault, "home", &fx.window)
            .unwrap()
            .oplog_vv();
        let envelope = transport::WindowPadEnvelope {
            kind: transport::WindowPadKind::ResidenceUpdate,
            form: transport::WindowPadForm::PadFree,
            queue_seq: Some(1),
            payload: update,
            refs: Vec::new(),
            sidecar: None,
        };
        for frame in envelope
            .encode_frames(fx.window.as_str(), window_sub_tags::RESIDENCE_UPDATE)
            .unwrap()
        {
            send_binary(&mut socket, frame).await;
        }
        expect_close(&mut socket, REFUSED_FRAME).await;
        assert_eq!(fx.vault.get_raw(&fx.item).unwrap(), Some(original));
        assert_eq!(
            load_window_from_state(&fx.vault, "home", &fx.window)
                .unwrap()
                .oplog_vv(),
            before_update,
            "the refused edit appended no durable window operations"
        );
        let mut still_live = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let answer = rpc(&mut still_live, 2, "residence.index", json!({
            "window": fx.window.as_str(), "selector": encoded_selector(&fx.selector), "limit": 16
        })).await;
        assert_eq!(answer["items"], json!([]));
    });
}

#[test]
fn the_catalogue_never_names_a_window_it_does_not_list() {
    run_on_engine_stack(|| async {
        let fx = fixture_with_options(
            WindowFixture::Selected,
            FixtureOptions {
                empty_world_windows: 260,
                ..Default::default()
            },
        )
        .await;
        let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let mut after = None::<String>;
        let mut pages = Vec::new();
        let mut request_id = 2;
        loop {
            let page = rpc_within(
                &mut socket,
                request_id,
                "residence.windows",
                json!({
                    "selector": encoded_selector(&fx.selector),
                    "months": ["2026-03"], "limit": 16, "after": after
                }),
                CATALOGUE_WAIT,
            )
            .await;
            let next = page["next"].as_str().map(str::to_owned);
            if let Some(next) = next.as_deref() {
                assert!(
                    page["windows"].as_array().unwrap().contains(&json!(next)),
                    "a catalogue continuation must name a window listed on its page"
                );
                assert!(
                    after.as_deref().is_none_or(|previous| next > previous),
                    "a catalogue continuation must advance"
                );
            }
            pages.push(page);
            let Some(next) = next else {
                break;
            };
            after = Some(next);
            request_id += 1;
        }
        assert_eq!(pages.len(), 1);
        assert_eq!(pages[0]["windows"], json!(["2026-03"]));
        assert!(pages[0]["next"].is_null());
    });
}

#[test]
fn a_member_grant_bounded_to_a_world_writes_in_that_world() {
    run_on_engine_stack(|| async {
        let fx = fixture_with_options(
            WindowFixture::PortableWorld,
            FixtureOptions {
                bound_grant_to_world: true,
                ..Default::default()
            },
        )
        .await;
        let world = fx.world.unwrap();
        assert_eq!(
            fx.grant.authority_scope.worlds,
            ScopeAxis::Some(BTreeSet::from([ScopeId(world)]))
        );
        assert_eq!(fx.caller.slip.claims.scope, fx.grant.authority_scope);
        let original = fx.vault.get_raw(&fx.item).unwrap().unwrap();
        let mut socket = bound_member(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        let index = rpc(
            &mut socket,
            2,
            "residence.index",
            json!({
                "window": fx.window.as_str(),
                "selector": encoded_selector(&fx.selector), "limit": 16
            }),
        )
        .await;
        assert!(
            index["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["entity_id"] == fx.item.to_hex())
        );
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::PROMOTION_REQUEST,
            &encode_sync_selector(&fx.selector).unwrap(),
        )
        .await;
        let granted = next_member_binary(&mut socket).await;
        assert_eq!(granted[0], transport::TAG_WINDOW_SYNC);
        let (key, tag, payload) = transport::decode_window_sync(&granted[1..]).unwrap();
        assert_eq!(key, fx.window.as_str());
        assert_eq!(tag, window_sub_tags::PROMOTION_GRANTED);
        assert!(payload.is_empty());

        let persisted = load_window_from_state(&fx.vault, "home", &fx.window).unwrap();
        let peer = persisted.fork();
        let before_edit = peer.oplog_vv();
        let changed = public_world_claim(fx.member, world, "written by bounded member");
        let mut raw = original[..ENTITY_METADATA_HEADER_LEN].to_vec();
        raw.extend_from_slice(&encode_claim_body(&changed).unwrap());
        assert_ne!(raw, original);
        peer.get_map("entities")
            .insert(&fx.item.to_hex(), raw.as_slice())
            .unwrap();
        peer.commit();
        let update = peer.export(ExportMode::updates(&before_edit)).unwrap();
        assert!(!update.is_empty());
        let envelope = transport::WindowPadEnvelope {
            kind: transport::WindowPadKind::ResidenceUpdate,
            form: transport::WindowPadForm::PadFree,
            queue_seq: Some(1),
            payload: update,
            refs: Vec::new(),
            sidecar: None,
        };
        for frame in envelope
            .encode_frames(fx.window.as_str(), window_sub_tags::RESIDENCE_UPDATE)
            .unwrap()
        {
            send_binary(&mut socket, frame).await;
        }
        let ack = next_member_binary(&mut socket).await;
        assert_eq!(ack[0], transport::TAG_WINDOW_SYNC);
        let (key, tag, payload) = transport::decode_window_sync(&ack[1..]).unwrap();
        assert_eq!(key, fx.window.as_str());
        assert_eq!(tag, window_sub_tags::RESIDENCE_ACK);
        let receipt = transport::WindowPadReceipt::decode(payload).unwrap();
        assert_eq!(receipt.binding, envelope.binding());
        assert_eq!(receipt.readiness, transport::WindowPadReadiness::PadFree);
        let landed = load_window_from_state(&fx.vault, "home", &fx.window).unwrap();
        let Some(loro::ValueOrContainer::Value(loro::LoroValue::Binary(bytes))) =
            landed.get_map("entities").get(&fx.item.to_hex())
        else {
            panic!("the accepted update must persist the claim's bytes");
        };
        assert_eq!(bytes.as_slice(), raw.as_slice());

        send_rpc(&mut socket, 3, "ping", json!({"after": "accepted write"})).await;
        let ping_frame = next_member_binary(&mut socket).await;
        assert_eq!(ping_frame[0], transport::TAG_RPC);
        let ping_reply: Envelope<Value> = rmp_serde::from_slice(&ping_frame[1..]).unwrap();
        assert_eq!(ping_reply.kind, "ping");
        assert_eq!(ping_reply.id, 3);
        assert_eq!(ping_reply.seq, 0);
        assert!(ping_reply.last);
        assert_eq!(ping_reply.payload, json!({"after": "accepted write"}));
        let mut control = bound_member(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        let answer = rpc(
            &mut control,
            2,
            "residence.index",
            json!({
                "window": fx.window.as_str(),
                "selector": encoded_selector(&fx.selector), "limit": 16
            }),
        )
        .await;
        assert!(
            answer["items"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["entity_id"] == fx.item.to_hex())
        );
    });
}

/// OPUS-SECREAD-B #8363 F1: a member's residence update in the Sealed envelope
/// form installs nothing into the home's pad custody. The update carries a
/// capsule sealed to the home machine naming one pad of the window's world
/// that the update does not owe; the home answers `NotReady` and the pad is
/// absent from its custody after the send. The capsule comes from the
/// `oneiron_test_support` door that seals it, so this test compiles only
/// under that cfg.
#[cfg(oneiron_test_support)]
#[test]
fn a_members_sealed_pad_capsule_installs_nothing_in_the_homes_custody() {
    run_on_engine_stack(|| async {
        let fx = fixture_with_options(
            WindowFixture::PortableWorld,
            FixtureOptions {
                bound_grant_to_world: true,
                ..Default::default()
            },
        )
        .await;
        let world = fx
            .world
            .expect("the portable-world fixture names its world");
        let original = fx
            .vault
            .get_raw(&fx.item)
            .expect("the fixture claim reads")
            .expect("the fixture claim exists");
        let mut socket = bound_member(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        let index = rpc(
            &mut socket,
            2,
            "residence.index",
            json!({
                "window": fx.window.as_str(),
                "selector": encoded_selector(&fx.selector), "limit": 16
            }),
        )
        .await;
        assert!(
            index["items"]
                .as_array()
                .expect("the index lists its rows")
                .iter()
                .any(|row| row["entity_id"] == fx.item.to_hex())
        );
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::PROMOTION_REQUEST,
            &encode_sync_selector(&fx.selector).expect("the fixture selector encodes"),
        )
        .await;
        let granted = next_member_binary(&mut socket).await;
        assert_eq!(granted[0], transport::TAG_WINDOW_SYNC);
        let (key, tag, payload) =
            transport::decode_window_sync(&granted[1..]).expect("the promotion answer decodes");
        assert_eq!(key, fx.window.as_str());
        assert_eq!(tag, window_sub_tags::PROMOTION_GRANTED);
        assert!(payload.is_empty());

        let persisted = load_window_from_state(&fx.vault, "home", &fx.window)
            .expect("the promoted window loads");
        let peer = persisted.fork();
        let before_edit = peer.oplog_vv();
        let changed = public_world_claim(fx.member, world, "sealed by a member");
        let mut raw = original[..ENTITY_METADATA_HEADER_LEN].to_vec();
        raw.extend_from_slice(&encode_claim_body(&changed).expect("the claim encodes"));
        peer.get_map("entities")
            .insert(&fx.item.to_hex(), raw.as_slice())
            .expect("the peer takes the edit");
        peer.commit();
        let update = peer
            .export(ExportMode::updates(&before_edit))
            .expect("the edit exports");
        assert!(!update.is_empty());

        // One pad of the window's world the update does not owe, sealed to
        // the home machine: the capsule a member must not install with.
        let probe =
            oneiron::test_doors::sealed_pad_capsule::seal_pad_for_home_machine(&fx.vault, world)
                .expect("a capsule sealed to the home machine");
        let item = probe.item;
        assert!(
            !oneiron::test_doors::sealed_pad_capsule::world_pad_held(&fx.vault, &item)
                .expect("custody reads"),
            "the home holds no pad for the probe key before the update"
        );
        let envelope = transport::WindowPadEnvelope {
            kind: transport::WindowPadKind::ResidenceUpdate,
            form: transport::WindowPadForm::Sealed,
            queue_seq: Some(1),
            payload: update,
            refs: vec![item],
            sidecar: Some(transport::WindowPadSidecar {
                recipient: probe.recipient,
                source_position: probe.source_position,
                digest: probe.digest,
                capsule: probe.capsule,
            }),
        };
        for frame in envelope
            .encode_frames(fx.window.as_str(), window_sub_tags::RESIDENCE_UPDATE)
            .expect("the sealed envelope encodes")
        {
            send_binary(&mut socket, frame).await;
        }
        let ack = next_member_binary(&mut socket).await;
        assert_eq!(ack[0], transport::TAG_WINDOW_SYNC);
        let (key, tag, payload) =
            transport::decode_window_sync(&ack[1..]).expect("the acknowledgment decodes");
        assert_eq!(key, fx.window.as_str());
        assert_eq!(tag, window_sub_tags::RESIDENCE_ACK);
        let receipt =
            transport::WindowPadReceipt::decode(payload).expect("the ack carries a pad receipt");
        assert_eq!(receipt.binding, envelope.binding());
        assert_eq!(receipt.readiness, transport::WindowPadReadiness::NotReady);
        assert!(
            !oneiron::test_doors::sealed_pad_capsule::world_pad_held(&fx.vault, &item)
                .expect("custody reads"),
            "the sealed capsule installed nothing into the home's custody"
        );
    });
}

/// Review round 1 of #8364 (P1-2, server): a member lane's refused promotion
/// is answered `FOLLOW_REFUSED` and the socket stays open. `other_window`
/// holds a row the lane's selector does not select, so its promotion is
/// refused, while the selected window's promotion is granted on the same
/// socket right after, proving the socket is still open.
/// red at 40cf5d7d8818: the refused promotion closes the socket with
/// DECODE_ERROR instead of answering `FOLLOW_REFUSED`.
#[test]
fn a_refused_member_promotion_answers_follow_refused_and_keeps_the_socket() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let before = durable_rows(&fx);
        let mut socket = bound_member(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &fx.other_window,
            window_sub_tags::PROMOTION_REQUEST,
            &encode_sync_selector(&fx.selector).unwrap(),
        )
        .await;
        let refused = next_member_binary(&mut socket).await;
        assert_eq!(refused[0], transport::TAG_WINDOW_SYNC);
        let (key, tag, payload) = transport::decode_window_sync(&refused[1..]).unwrap();
        assert_eq!(key, fx.other_window.as_str());
        assert_eq!(tag, window_sub_tags::FOLLOW_REFUSED);
        assert!(payload.is_empty());
        // The socket is still open: the selected window's promotion is
        // granted on it.
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::PROMOTION_REQUEST,
            &encode_sync_selector(&fx.selector).unwrap(),
        )
        .await;
        let granted = next_member_binary(&mut socket).await;
        assert_eq!(granted[0], transport::TAG_WINDOW_SYNC);
        let (key, tag, payload) = transport::decode_window_sync(&granted[1..]).unwrap();
        assert_eq!(key, fx.window.as_str());
        assert_eq!(tag, window_sub_tags::PROMOTION_GRANTED);
        assert!(payload.is_empty());
        assert_eq!(durable_rows(&fx), before);
    });
}

/// Review round 1 of #8364 (P1-3, server): a member lane reads its window's
/// tombstone id set. After HOME hard-deletes the selected item,
/// `residence.tombstones` answers a page that lists its id with the hard
/// delete's value.
/// red at 40cf5d7d8818: the method is not on the member lane's RPC
/// allow-list, so the call closes the socket with DECODE_ERROR instead of
/// answering a page.
#[test]
fn a_member_lane_reads_its_windows_tombstones() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let mut socket = bound_member(&fx, transport::PROTOCOL_VERSION).await;
        let selector = encoded_selector(&fx.selector);
        let index = rpc(
            &mut socket,
            2,
            "residence.index",
            json!({
                "window": fx.window.as_str(), "selector": selector, "limit": 16
            }),
        )
        .await;
        assert_eq!(index["items"][0]["entity_id"], fx.item.to_hex());
        assert!(
            fx.vault
                .delete_entity_with_reason(&fx.item, DeleteReason::UserHardDelete)
                .unwrap()
                .existed,
            "HOME hard-deletes the selected item"
        );
        // The client's own call shape (`SyncClient::fetch_tombstones_of`):
        // window, selector, id cursor and limit, exactly as the server reads
        // them.
        let cursor: Option<String> = None;
        let page = rpc(
            &mut socket,
            3,
            "residence.tombstones",
            json!({
                "window": fx.window.as_str(), "selector": selector,
                "after": cursor, "limit": 16
            }),
        )
        .await;
        assert_eq!(page["window"], json!(fx.window.as_str()));
        let items = page["items"].as_array().unwrap();
        assert!(
            items
                .iter()
                .any(|entry| entry["entityId"] == fx.item.to_hex()),
            "the hard-deleted id is listed: {page}"
        );
        let listed = items
            .iter()
            .find(|entry| entry["entityId"] == fx.item.to_hex())
            .unwrap();
        let value = base64::engine::general_purpose::STANDARD
            .decode(listed["value"].as_str().unwrap())
            .unwrap();
        assert_eq!(value.first(), Some(&2), "the hard delete's reason byte");
        assert_eq!(value.len(), 25, "the whole tombstone value");
    });
}

/// FOLLOW-REQUEST-WINDOW-LIST-ORACLE (SYNC-RECEIVE-READ-20261127 F11): a
/// member lane gets no root, so a follow or promotion with a garbage selector
/// gets one answer whether or not the home lists the window: the socket
/// closes with DECODE_ERROR, and nothing is answered with the socket kept.
/// red with the selector decode moved back after the root's list check: the
/// unlisted window is answered `FOLLOW_REFUSED` and its socket stays open,
/// while the listed window's socket closes.
#[test]
fn a_garbage_follow_selector_gets_one_answer_for_a_listed_and_an_unlisted_window() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let unlisted = WindowKey::try_new("2019-07").unwrap();
        for sub_tag in [
            window_sub_tags::FOLLOW_REQUEST,
            window_sub_tags::PROMOTION_REQUEST,
        ] {
            for key in [&fx.window, &unlisted] {
                let mut socket = bound_member(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
                send_window(&mut socket, key, sub_tag, b"not a selector").await;
                expect_close(&mut socket, REFUSED_FRAME).await;
            }
        }
    });
}

/// The same order keeps the honest answer: a well-formed follow of a window
/// the home does not list is still answered `FOLLOW_REFUSED`, and the socket
/// stays open, so the listed window's promotion is granted on it right after.
#[test]
fn a_well_formed_follow_of_an_unlisted_window_still_answers_follow_refused() {
    run_on_engine_stack(|| async {
        let fx = fixture(WindowFixture::Selected).await;
        let unlisted = WindowKey::try_new("2019-07").unwrap();
        let selector = encode_sync_selector(&fx.selector).unwrap();
        let mut socket = bound_member(&fx, transport::RESIDENCE_PROTOCOL_VERSION).await;
        send_window(
            &mut socket,
            &unlisted,
            window_sub_tags::FOLLOW_REQUEST,
            &selector,
        )
        .await;
        let refused = next_member_binary(&mut socket).await;
        assert_eq!(refused[0], transport::TAG_WINDOW_SYNC);
        let (key, tag, payload) = transport::decode_window_sync(&refused[1..]).unwrap();
        assert_eq!(key, unlisted.as_str());
        assert_eq!(tag, window_sub_tags::FOLLOW_REFUSED);
        assert!(payload.is_empty());
        send_window(
            &mut socket,
            &fx.window,
            window_sub_tags::PROMOTION_REQUEST,
            &selector,
        )
        .await;
        let granted = next_member_binary(&mut socket).await;
        assert_eq!(granted[0], transport::TAG_WINDOW_SYNC);
        let (key, tag, payload) = transport::decode_window_sync(&granted[1..]).unwrap();
        assert_eq!(key, fx.window.as_str());
        assert_eq!(tag, window_sub_tags::PROMOTION_GRANTED);
        assert!(payload.is_empty());
    });
}
