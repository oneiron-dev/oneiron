//! A selector socket answer to another vault's machine carries the owner's
//! delete of a row an earlier answer under the same grant sent it
//! (CROSS-VAULT-DELETE-SELECTOR-ANSWER-RELEASE; ruling
//! CROSS-VAULT-DELETE-NEVER-ADMITTED = A, Oneiron lead 21 Nov 06:1x: "while
//! the share is live, the owner's delete travels as an update and removes the
//! peer's copy"), through the real `/ws` door: owner-grade upgrade, the
//! current selector hello, an in-band `auth.bind` of the member's own slip,
//! and `SELECTOR_VV_REQUEST`s for the claim's window (the
//! `handle_selector_fetch` door). The socket proves no machine of this
//! vault's, so it is served as another vault's.
//!
//! Before: the socket filtered with no tombstone at all and recorded no
//! release, so a row that only a socket answer sent never got its delete
//! there. After: each answer's rows are recorded at its last door before its
//! bytes leave, and a later answer carries the owner's delete of each, and of
//! no row it never sent. The peer's own delivery ledger then decides whether
//! its copy goes (`federated_record_tombstone_admission.rs` in `oneiron`).
//!
//! - `a_socket_answers_row_delete_follows_it_to_the_peer`: red on main (the
//!   second answer carries no tombstone), green on the head.
//! - `a_delete_of_a_row_no_answer_sent_stays_home`: guard, green on both.
//!
//! Needs the `oneiron/test-hooks` feature (`put_selector_test_federation_grant`)
//! and its `[[test]]` stanza.
//!
//! `cargo test --locked -p oneiron-server --features oneiron/test-hooks
//! --test selector_answer_carries_released_row_delete`.

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
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, DeleteReason,
    EntityId, TimeRange, Vault, VaultConfig,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const SECRET: &str = "selector-answer-release-test-owner";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
}

/// One stated CLAIM about `subject` holding `text` and learned at `now`.
fn seed_claim(vault: &Vault, subject: EntityId, text: &str, now: u64) -> EntityId {
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

/// The served vault, the claims' subject and learning time, one claim, and
/// the selector that fetches its window.
struct Seeded {
    fixture: Fixture,
    key: String,
    selector: SyncSelector,
    member: EntityId,
    subject: EntityId,
    now: u64,
    claim: EntityId,
}

/// Seeds the vault (the member, the claim's subject, one claim, the
/// member's co-Owner grant, so every row's label is the member's to read)
/// and serves it. The window cold-opens on the first fetch.
async fn fixture() -> Seeded {
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
    let claim = seed_claim(&vault, subject, "a shared note", now);

    let grant_id = EntityId::now();
    let mut grant = FederationGrant::new(
        own_device_residence_scope(),
        member,
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
    );
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
        subject,
        now,
        claim,
    }
}

struct Credential {
    slip: CapabilitySlip,
    holder: ed25519_dalek::SigningKey,
}

/// A valid unattenuated slip for `member`: `read` verbs, every other axis
/// open, holder ref the member, bound to its holder key.
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
    let holder = ed25519_dalek::SigningKey::from_bytes(&[94; 32]);
    claims.binding_key = holder.verifying_key().to_bytes();
    let slip = server
        .vault()
        .mint_capability_slip(&issuer, claims)
        .expect("the member's slip");
    Credential { slip, holder }
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

/// Owner-grade upgrade, then the current selector hello.
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
/// `{type, id, seq, last, payload}`.
#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    #[serde(rename = "type")]
    kind: String,
    id: u64,
    seq: u64,
    last: bool,
    payload: T,
}

/// Binds `credential` in-band, stamped at the served vault's recorded clock,
/// and checks the bind's terminal reply.
async fn bind(seeded: &Seeded, socket: &mut Socket, credential: &Credential, request_id: u64) {
    let timestamp = seeded.fixture.server.vault().now_recorded_at();
    let envelope = Envelope {
        kind: "rpc.req".to_owned(),
        id: request_id,
        seq: 0,
        last: true,
        payload: json!({"method":"auth.bind","params":bind_payload(credential, timestamp)}),
    };
    let mut data = vec![TAG_RPC];
    envelope
        .serialize(&mut rmp_serde::Serializer::new(&mut data).with_struct_map())
        .expect("envelope encodes");
    socket
        .send(Message::Binary(data.into()))
        .await
        .expect("rpc sends");
    let mut reply = Vec::new();
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
        reply.extend_from_slice(&envelope.payload);
        if envelope.last {
            let result: Json = rmp_serde::from_slice(&reply).expect("an rpc result decodes");
            assert_eq!(result, Json::Null, "FIXTURE: the bind succeeds");
            return;
        }
    }
}

/// Sends the selector fetch for the claim's window and imports the served
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

/// The row ids `doc`'s map `name` holds.
fn map_keys(doc: &LoroDoc, name: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    doc.get_map(name).for_each(|key, _| {
        keys.insert(key.to_owned());
    });
    keys
}

/// The owner hard-deletes `id`; the vault holds no row of it after.
fn hard_delete(seeded: &Seeded, id: &EntityId) {
    let vault = seeded.fixture.server.vault();
    let outcome = vault
        .delete_entity_with_reason(id, DeleteReason::UserHardDelete)
        .expect("FIXTURE: the owner hard-deletes the row");
    assert!(outcome.existed, "FIXTURE: the deleted row existed");
    assert!(
        vault.get_raw(id).expect("FIXTURE: row reads").is_none(),
        "FIXTURE: the vault holds no row after its hard delete"
    );
}

#[tokio::test]
async fn a_socket_answers_row_delete_follows_it_to_the_peer() {
    let seeded = fixture().await;
    let mut socket = connect(&seeded).await;
    let credential = credential(&seeded.fixture.server, seeded.member);
    bind(&seeded, &mut socket, &credential, 5).await;
    let first = fetch(&seeded, &mut socket).await;
    assert!(
        map_keys(&first, "entities").contains(&seeded.claim.to_hex()),
        "FIXTURE: the first answer carries the claim"
    );

    hard_delete(&seeded, &seeded.claim);
    let second = fetch(&seeded, &mut socket).await;
    assert!(
        !map_keys(&second, "entities").contains(&seeded.claim.to_hex()),
        "FIXTURE: the second answer carries no body of the deleted claim"
    );
    let carried = map_keys(&second, "tombstones");
    assert!(
        carried.contains(&seeded.claim.to_hex()),
        "NO-DELETE-SENT: the next socket answer under the grant omits the owner's delete of a \
         row an earlier answer sent the peer: {carried:?}"
    );
}

#[tokio::test]
async fn a_delete_of_a_row_no_answer_sent_stays_home() {
    let seeded = fixture().await;
    let mut socket = connect(&seeded).await;
    let credential = credential(&seeded.fixture.server, seeded.member);
    bind(&seeded, &mut socket, &credential, 5).await;
    let first = fetch(&seeded, &mut socket).await;
    assert!(
        map_keys(&first, "entities").contains(&seeded.claim.to_hex()),
        "FIXTURE: the first answer carries the claim"
    );

    // Written and deleted between two answers: no answer ever sent it.
    let unsent = seed_claim(
        seeded.fixture.server.vault(),
        seeded.subject,
        "a note no answer carried",
        seeded.now,
    );
    hard_delete(&seeded, &unsent);
    hard_delete(&seeded, &seeded.claim);
    let second = fetch(&seeded, &mut socket).await;
    let carried = map_keys(&second, "tombstones");
    assert!(
        !carried.contains(&unsent.to_hex()),
        "LEAK: the socket answer names the delete of a row no answer sent the peer: {carried:?}"
    );
}
