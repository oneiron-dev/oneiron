//! A served selector fetch carries no stamped claim to a member homed
//! elsewhere (L5-02 PR 4, RULING SECREAD-HOME-SELECTOR-EXPORT = A), through
//! the real `/ws` door: owner-grade upgrade, the current selector (v9)
//! hello, an in-band `auth.bind` of the member's own slip, and a
//! `SELECTOR_VV_REQUEST` for the claims' window (the
//! `handle_selector_fetch` door, which answers with
//! `filtered_window_doc_for_peer`'s Loro export).
//!
//! The vault holds four claims about one PERSON (one unstamped, one
//! `public`, one `private`, one `sensitive`) and a live Member federation
//! grant for a non-owner PERSON member. The member binds its own valid
//! unattenuated slip (`read` verbs, every other axis open, holder ref the
//! member). The first test asserts the served window carries the unstamped
//! and `public` claims and neither stamped one; a second test repeats the
//! fetch under an Owner-role grant and asserts all four ride it.
//!
//! Needs the `oneiron/test-hooks` feature (`put_selector_test_federation_grant`)
//! and its `[[test]]` stanza (see NOTES.md).
//!
//! `cargo test --locked -p oneiron-server --features oneiron/test-hooks
//! --test selector_home_clearance_ws`.

use std::collections::BTreeSet;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use loro::LoroDoc;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, Scope, ScopeAxis,
    own_device_residence_scope,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::sync::transport::{self, TAG_RPC, TAG_WINDOW_SYNC, window_sub_tags};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, encode_selector_vv_request,
    put_selector_test_federation_grant,
};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const SECRET: &str = "selector-home-clearance-test-owner";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// One stated CLAIM about `subject` holding `text` and learned at `now`,
/// stamped `sensitivity` when a band is named.
fn seed_claim(
    vault: &Vault,
    subject: EntityId,
    text: &str,
    sensitivity: Option<&str>,
    now: u64,
) -> EntityId {
    let id = EntityId::now();
    let mut body = ClaimBody::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("claim body");
    body.source = Some(ClaimSource::UserStated);
    if let Some(band) = sensitivity {
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from(band),
        )]));
    }
    vault.put_claim(&id, &body, at(now), now).expect("a record");
    id
}

struct Fixture {
    task: tokio::task::JoinHandle<()>,
    url: String,
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The four claims the served window holds, and the selector that fetches it.
struct Seeded {
    fixture: Fixture,
    key: String,
    selector: SyncSelector,
    member: EntityId,
    unstamped: EntityId,
    public: EntityId,
    private_claim: EntityId,
    sensitive_claim: EntityId,
}

/// Seeds the vault (the member, the four claims, the member's grant of
/// `role`) and serves it. The window cold-opens on the first fetch, and the
/// open reverse-rematerializes the seeded rows into it.
async fn fixture(role: FederationGrantRole, preset: FederationGrantPreset) -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault"));
    let now = vault.now_recorded_at();
    let member = EntityId::now();
    let person_body = rmp_serde::to_vec_named(&json!({ "name": "member" })).expect("member body");
    vault
        .put_entity(&member, ENTITY_TYPE_PERSON, at(now), now, &person_body)
        .expect("a member PERSON");
    let subject = EntityId::now();
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at(now), now, &person_body)
        .expect("the claims' subject");
    let unstamped = seed_claim(&vault, subject, "an unstamped note", None, now);
    let public = seed_claim(&vault, subject, "a public note", Some("public"), now);
    let private_claim = seed_claim(&vault, subject, "a private note", Some("private"), now);
    let sensitive_claim = seed_claim(&vault, subject, "a sensitive note", Some("sensitive"), now);

    let scope = own_device_residence_scope();
    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(scope, member, role, preset);
    // The `read_preset` scope, built inline: `read` verbs, every other axis
    // open, so the role is the only difference between the two tests.
    let mut authority = Scope::top();
    authority.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    grant.authority_scope = authority;
    put_selector_test_federation_grant(&vault, &grant_id, &grant, now)
        .expect("the member's federation grant");
    let selector = SyncSelector::new(grant_id, member, SyncSelectorWorld::All, vec![], vec![]);
    let key = WindowKey::from_timestamp(now).as_str().to_owned();

    let server = Arc::new(
        SyncServer::new(
            vault,
            SyncServerConfig {
                auth_secret: Some(SECRET.to_owned()),
                ..Default::default()
            },
        )
        .expect("test server"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener");
    let url = format!(
        "ws://{}/ws",
        listener.local_addr().expect("listener address")
    );
    let app = build_app(server.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve the app");
    });
    Seeded {
        fixture: Fixture {
            task,
            url,
            _dir: dir,
            server,
        },
        key,
        selector,
        member,
        unstamped,
        public,
        private_claim,
        sensitive_claim,
    }
}

struct Credential {
    slip: CapabilitySlip,
    holder: ed25519_dalek::SigningKey,
}

/// A valid unattenuated slip for `member`: `read` verbs, every other axis
/// open (facets unnarrowed), holder ref the member, bound to its holder key.
fn credential(server: &SyncServer, member: EntityId) -> Credential {
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).expect("host issuer");
    let mut claims = server
        .vault()
        .ensure_host_root_slip(&issuer)
        .expect("host root slip")
        .claims;
    claims.slip_id = *blake3::hash(member.as_bytes()).as_bytes();
    claims.holder_ref = member.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let holder = ed25519_dalek::SigningKey::from_bytes(&[93; 32]);
    claims.binding_key = holder.verifying_key().to_bytes();
    let slip = server
        .vault()
        .mint_capability_slip(&issuer, claims)
        .expect("the member's slip");
    Credential { slip, holder }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock")
        .as_secs()
}

fn bind_payload(credential: &Credential, timestamp: u64) -> Json {
    use ed25519_dalek::Signer;
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = credential
        .holder
        .sign(
            &credential
                .slip
                .binding_transcript(challenge.as_bytes())
                .expect("binding transcript"),
        )
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    json!({"token":credential.slip.to_token().expect("slip token"),"binding":{"timestamp":timestamp,"nonce":nonce,"signature":signature}})
}

fn host_root_binding(fixture: &Fixture) -> (String, Json) {
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).expect("host issuer");
    let slip = fixture
        .server
        .vault()
        .ensure_host_root_slip(&issuer)
        .expect("host root slip");
    let timestamp = fixture.server.vault().now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .expect("binding proof")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    (
        slip.to_token().expect("slip token"),
        json!({"timestamp":timestamp,"nonce":nonce,"signature":signature}),
    )
}

/// Owner-grade upgrade, then the current selector (v9) hello.
async fn connect(seeded: &Seeded) -> Socket {
    let mut request = seeded
        .fixture
        .url
        .as_str()
        .into_client_request()
        .expect("client request");
    let (token, binding) = host_root_binding(&seeded.fixture);
    request.headers_mut().insert(
        "authorization",
        format!("Bearer {token}").parse().expect("bearer"),
    );
    request.headers_mut().insert(
        "x-oneiron-binding",
        binding.to_string().parse().expect("binding"),
    );
    let (mut socket, _) = tokio_tungstenite::connect_async(request)
        .await
        .expect("websocket upgrade");
    socket
        .send(Message::Binary(transport::encode_protocol_hello().into()))
        .await
        .expect("selector hello");
    let root = next(&mut socket).await;
    assert!(
        matches!(root, Message::Binary(ref data) if data[0] == 0),
        "the upgrade answers the root snapshot"
    );
    socket
}

async fn next(socket: &mut Socket) -> Message {
    tokio::time::timeout(std::time::Duration::from_secs(10), socket.next())
        .await
        .expect("a websocket message arrives")
        .expect("the socket stays open")
        .expect("no socket error")
}

/// The app envelope the server speaks: TAG + MessagePack
/// `{type, id, seq, last, payload}`. Requests are terminal at seq zero; RPC
/// results arrive as `rpc.res` chunks whose payloads concatenate into one
/// MessagePack value.
#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    #[serde(rename = "type")]
    kind: String,
    id: u64,
    seq: u64,
    last: bool,
    payload: T,
}

async fn send(socket: &mut Socket, tag: u8, mut value: Json) {
    let object = value.as_object_mut().expect("an rpc object");
    let id = object
        .remove("requestId")
        .or_else(|| object.remove("subscriptionId"))
        .and_then(|id| id.as_u64())
        .expect("a request id");
    let kind = if tag == TAG_RPC {
        "rpc.req".to_owned()
    } else {
        object
            .remove("method")
            .expect("a method")
            .as_str()
            .expect("a method name")
            .to_owned()
    };
    let envelope = Envelope {
        kind,
        id,
        seq: 0,
        last: true,
        payload: value,
    };
    let mut data = vec![tag];
    envelope
        .serialize(&mut rmp_serde::Serializer::new(&mut data).with_struct_map())
        .expect("envelope encodes");
    socket
        .send(Message::Binary(data.into()))
        .await
        .expect("rpc sends");
}

/// Reassembles one `rpc.res` reply from its chunk frames into the
/// `{requestId, result, last}` shape the assertions pin.
async fn rpc_reply(socket: &mut Socket) -> Json {
    let mut data = Vec::new();
    let mut next_seq = 0;
    loop {
        let frame = match next(socket).await {
            Message::Binary(frame) => frame,
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected a bind response, got {other:?}"),
        };
        assert_eq!(frame[0], TAG_RPC);
        let envelope: Envelope<serde_bytes::ByteBuf> =
            rmp_serde::from_slice(&frame[1..]).expect("an rpc envelope decodes");
        assert_eq!(envelope.kind, "rpc.res");
        assert_eq!(envelope.seq, next_seq);
        next_seq += 1;
        data.extend_from_slice(&envelope.payload);
        if envelope.last {
            let result: Json = rmp_serde::from_slice(&data).expect("an rpc result decodes");
            return json!({"requestId": envelope.id, "result": result, "last": true});
        }
    }
}

/// Binds `credential` in-band and checks the bind's terminal reply.
async fn bind(socket: &mut Socket, credential: &Credential, request_id: u64) {
    send(
        socket,
        TAG_RPC,
        json!({"requestId":request_id,"method":"auth.bind","params":bind_payload(credential, now())}),
    )
    .await;
    assert_eq!(
        rpc_reply(socket).await,
        json!({"requestId":request_id,"result":null,"last":true})
    );
}

/// Sends the selector fetch for the claims' window and imports the served
/// UPDATE into a fresh window doc. Root notices pass through; one durable
/// deferral is retried on this socket.
async fn fetch(seeded: &Seeded, socket: &mut Socket) -> LoroDoc {
    let request =
        encode_selector_vv_request(&seeded.selector, &loro::VersionVector::default().encode())
            .expect("selector request encodes");
    let fetch =
        transport::encode_window_sync(&seeded.key, window_sub_tags::SELECTOR_VV_REQUEST, &request)
            .into_result()
            .expect("selector fetch encodes");
    socket
        .send(Message::Binary(fetch.into()))
        .await
        .expect("selector fetch sends");
    let doc = LoroDoc::new();
    let _ = doc.get_map("entities");
    let _ = doc.get_map("edges");
    let _ = doc.get_map("tombstones");
    doc.commit();
    let mut retried = false;
    loop {
        let frame = match next(socket).await {
            Message::Binary(frame) => frame.to_vec(),
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected a window frame, got {other:?}"),
        };
        if frame.first() != Some(&TAG_WINDOW_SYNC) {
            continue;
        }
        let (key, sub_tag, payload) =
            transport::decode_window_sync(&frame[1..]).expect("a window frame decodes");
        assert_eq!(key, seeded.key.as_str(), "the fetch answers its own window");
        if sub_tag == window_sub_tags::UPDATE {
            doc.import(payload).expect("the served update imports");
            return doc;
        }
        if sub_tag == window_sub_tags::SELECTOR_DEFERRED && !retried {
            retried = true;
            let retry = transport::encode_window_sync(
                &seeded.key,
                window_sub_tags::SELECTOR_RETRY,
                payload,
            )
            .into_result()
            .expect("selector retry encodes");
            socket
                .send(Message::Binary(retry.into()))
                .await
                .expect("selector retry sends");
            continue;
        }
        panic!("expected the served UPDATE, got sub-tag {sub_tag}");
    }
}

#[tokio::test]
async fn a_members_selector_fetch_carries_no_stamped_claim() {
    let seeded = fixture(FederationGrantRole::Member, FederationGrantPreset::Member).await;
    let vault = seeded.fixture.server.vault();
    for id in [
        seeded.unstamped,
        seeded.public,
        seeded.private_claim,
        seeded.sensitive_claim,
    ] {
        assert!(
            vault.get_raw(&id).expect("claim read").is_some(),
            "FIXTURE: the vault holds {}",
            id.to_hex()
        );
    }
    let mut socket = connect(&seeded).await;
    let credential = credential(&seeded.fixture.server, seeded.member);
    bind(&mut socket, &credential, 5).await;
    let doc = fetch(&seeded, &mut socket).await;
    let entities = doc.get_map("entities");
    assert!(
        entities.get(seeded.unstamped.to_hex().as_str()).is_some(),
        "FIXTURE: the served window carries the unstamped claim"
    );
    assert!(
        entities.get(seeded.public.to_hex().as_str()).is_some(),
        "the served window carries the public-stamped claim (control)"
    );
    let leaked: Vec<&str> = [
        (seeded.private_claim, "private"),
        (seeded.sensitive_claim, "sensitive"),
    ]
    .into_iter()
    .filter(|(id, _)| entities.get(id.to_hex().as_str()).is_some())
    .map(|(_, band)| band)
    .collect();
    assert!(
        leaked.is_empty(),
        "LEAK: the served window carries the {leaked:?}-stamped claims to a Member homed elsewhere"
    );
}

#[tokio::test]
async fn a_co_owners_selector_fetch_carries_every_claim() {
    let seeded = fixture(FederationGrantRole::Owner, FederationGrantPreset::Owner).await;
    let mut socket = connect(&seeded).await;
    let credential = credential(&seeded.fixture.server, seeded.member);
    bind(&mut socket, &credential, 5).await;
    let doc = fetch(&seeded, &mut socket).await;
    let entities = doc.get_map("entities");
    let withheld: Vec<&str> = [
        (seeded.unstamped, "unstamped"),
        (seeded.public, "public"),
        (seeded.private_claim, "private"),
        (seeded.sensitive_claim, "sensitive"),
    ]
    .into_iter()
    .filter(|(id, _)| entities.get(id.to_hex().as_str()).is_none())
    .map(|(_, band)| band)
    .collect();
    assert!(
        withheld.is_empty(),
        "OVER-REFUSAL: the served window withholds the {withheld:?} claims from a co-Owner"
    );
}
