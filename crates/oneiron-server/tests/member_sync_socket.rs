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
    FederationGrant, FederationGrantPreset, FederationGrantRole, FederationGrantScope,
    SharedVaultPreset,
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
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
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
const ROOT_OBSERVATION: Duration = Duration::from_millis(250);
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

struct Fixture {
    task: tokio::task::JoinHandle<()>,
    url: String,
    vault: Arc<Vault>,
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
        ClaimApprovalStatus::Proposed,
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
    let grant_id = EntityId::now();
    let grant = FederationGrant::new(
        FederationGrantScope::vault(42),
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
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
    let world = matches!(shape, WindowFixture::PortableWorld).then(EntityId::now);
    let window = world.map_or_else(|| month.clone(), |id| WindowKey::for_world(at, id));
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
    tokio::time::timeout(REPLY_WAIT, socket.next())
        .await
        .expect("a reply or explicit close, never silence")
        .expect("socket did not end")
        .expect("valid WebSocket frame")
}

async fn next_member_binary(socket: &mut Socket) -> Vec<u8> {
    loop {
        match next_message(socket).await {
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
    let mut bytes = Vec::new();
    let mut seq = 0;
    loop {
        let frame = next_member_binary(socket).await;
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
    send_rpc(socket, id, method, params).await;
    rpc_reply(socket, id)
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
