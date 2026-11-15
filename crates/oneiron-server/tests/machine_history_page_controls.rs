//! A machine-history page judges every history control (L5-02 PR 5, RULING
//! SECREAD-HOME-MACHINE-HISTORY = A), through the real `/ws` door: owner-grade
//! upgrade, the current selector (v9) hello, an in-band `auth.bind` of the
//! caller's own slip, and a `residence.machine-history` RPC for the target.
//!
//! The vault holds a machine-born CLAIM T, re-put by the vault owner as an
//! ordinary same-id successor. The successor closes the signed history but
//! keeps its controls, which copy the birth's scope, world, relationship and
//! facet. A member that reads the live T but not every control is refused the
//! whole page as not found; a co-Owner that reads every control is served
//! every row.
//!
//! A CLAIM's sensitivity is fixed at birth: a successor that re-puts a private
//! machine birth public is refused as a restamp (`record_scope/stamping.rs`),
//! so a private history always sits under a private target. Test 1 pins that
//! refusal and the member's refused page. Test 2 is the reachable leak: T is
//! born public but labelled with a relationship R the member does not read,
//! with a secret word W, and the successor drops the label (the label is no
//! part of the stamp): the co-Owner's page serves rows holding W, the
//! member's call is refused and no member reply holds W. Guard 3 is the
//! co-Owner alone on test 2's vault. Guard 4 births T public and unlabelled,
//! and the owner's ordinary successor makes it a readable target (a Proposed
//! machine birth is no surfaceable target): the member's page serves rows.
//!
//! Needs `oneiron/test-hooks` (`put_selector_test_federation_grant`) and
//! `oneiron/test-support` (`bind_host_owner`), plus its `[[test]]` stanza.
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --features oneiron/test-support,oneiron/test-hooks
//! --test machine_history_page_controls`.

use std::collections::BTreeSet;
use std::sync::Arc;

use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use loro::LoroDoc;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::federation::{
    FederationGrant, FederationGrantPreset, FederationGrantRole, Scope, ScopeAxis,
    own_device_residence_scope,
};
use oneiron::registry::{ENTITY_TYPE_MACHINE, ENTITY_TYPE_PERSON, ENTITY_TYPE_RELATIONSHIP};
use oneiron::sync::transport::{self, TAG_RPC, TAG_WINDOW_SYNC, window_sub_tags};
use oneiron::sync::{
    SyncSelector, SyncSelectorWorld, WindowKey, encode_selector_vv_request, encode_sync_selector,
    put_selector_test_federation_grant,
};
use oneiron::test_support::bind_host_owner;
use oneiron::write_envelope::MachineWriteSignature;
use oneiron::{
    ClaimApprovalStatus, ClaimCandidate, ClaimSource, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor, WriteEnvelope, WriteProvenance,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde::{Deserialize, Serialize};
use serde_json::{Value as Json, json};
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest};

type Socket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const SECRET: &str = "machine-history-page-controls-test-owner";
const PRIVATE_WORD: &str = "zxqw-private-birth-quixotic-42";
const REL_WORD: &str = "zxqw-relationship-birth-quixotic-43";

fn at(time: u64) -> TimeRange {
    TimeRange {
        start: time,
        end: time,
    }
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

struct Seeded {
    fixture: Fixture,
    key: String,
    member_selector: SyncSelector,
    co_owner_selector: SyncSelector,
    member: EntityId,
    co_owner: EntityId,
    target: EntityId,
    /// The refusal of the public successor `fixture_private` tries, if any.
    successor_refusal: Option<String>,
}

fn person_body() -> Vec<u8> {
    rmp_serde::to_vec_named(&json!({ "name": "member" })).expect("member body")
}

fn read_authority() -> Scope {
    let mut authority = Scope::top();
    authority.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    authority
}

struct Credential {
    slip: CapabilitySlip,
    holder: ed25519_dalek::SigningKey,
}

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

async fn fetch_for(selector: &SyncSelector, window: &str, socket: &mut Socket) -> LoroDoc {
    let request = encode_selector_vv_request(selector, &loro::VersionVector::default().encode())
        .expect("selector request encodes");
    let fetch =
        transport::encode_window_sync(window, window_sub_tags::SELECTOR_VV_REQUEST, &request)
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
        assert_eq!(key, window, "the fetch answers its own window");
        if sub_tag == window_sub_tags::UPDATE {
            doc.import(payload).expect("the served update imports");
            return doc;
        }
        if sub_tag == window_sub_tags::SELECTOR_DEFERRED && !retried {
            retried = true;
            let retry =
                transport::encode_window_sync(window, window_sub_tags::SELECTOR_RETRY, payload)
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

async fn history_page(
    socket: &mut Socket,
    selector: &SyncSelector,
    target: EntityId,
    request_id: u64,
) -> Result<Json, Json> {
    let encoded = encode_sync_selector(selector).expect("selector encodes");
    let selector_b64 = base64::engine::general_purpose::STANDARD.encode(encoded);
    send(
        socket,
        TAG_RPC,
        json!({"requestId":request_id,"method":"residence.machine-history","params":{"selector":selector_b64,"target":target.to_hex()}}),
    )
    .await;
    let mut data = Vec::new();
    let mut next_seq = 0;
    loop {
        let frame = match next(socket).await {
            Message::Binary(frame) => frame,
            Message::Ping(_) | Message::Pong(_) => continue,
            other => panic!("expected a history reply, got {other:?}"),
        };
        assert_eq!(frame[0], TAG_RPC);
        let peek: Envelope<rmpv::Value> =
            rmp_serde::from_slice(&frame[1..]).expect("an rpc envelope decodes");
        if peek.kind == "rpc.err" {
            let error: Envelope<Json> =
                rmp_serde::from_slice(&frame[1..]).expect("an rpc error decodes");
            assert_eq!(error.id, request_id);
            return Err(error.payload);
        }
        assert_eq!(peek.kind, "rpc.res");
        let chunk: Envelope<serde_bytes::ByteBuf> =
            rmp_serde::from_slice(&frame[1..]).expect("an rpc chunk decodes");
        assert_eq!(chunk.id, request_id);
        assert_eq!(chunk.seq, next_seq);
        next_seq += 1;
        data.extend_from_slice(&chunk.payload);
        if chunk.last {
            let result: Json = rmp_serde::from_slice(&data).expect("a history result decodes");
            return Ok(result);
        }
    }
}

fn page_contains_word(page: &Json, word: &str) -> bool {
    let Some(rows) = page.get("rows").and_then(|rows| rows.as_array()) else {
        return false;
    };
    rows.iter().any(|row| {
        let Some(raw) = row.get("raw").and_then(|raw| raw.as_str()) else {
            return false;
        };
        let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(raw) else {
            return false;
        };
        String::from_utf8_lossy(&decoded).contains(word)
    })
}

struct BirthSpec {
    machine: EntityId,
    signing: ed25519_dalek::SigningKey,
    subject: EntityId,
    target: EntityId,
    text: String,
    scope: Option<rmpv::Value>,
    relationship: Option<EntityId>,
    now: u64,
}

fn enroll_machine(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    machine: EntityId,
    signing: &ed25519_dalek::SigningKey,
) {
    use ed25519_dalek::Signer;
    vault
        .enroll_machine_identity(
            issuer,
            machine,
            signing.verifying_key().to_bytes(),
            [17; 32],
            |transcript| Ok(signing.sign(transcript).to_bytes()),
        )
        .expect("machine enrollment");
}

fn seed_machine_birth(vault: &Vault, spec: BirthSpec) {
    use ed25519_dalek::Signer;
    let BirthSpec {
        machine,
        signing,
        subject,
        target,
        text,
        scope,
        relationship,
        now,
    } = spec;
    let mut candidate = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text.as_str()),
        1.0,
    );
    if let Some(scope) = scope {
        candidate = candidate.with_scope(scope);
    }
    if let Some(relationship) = relationship {
        candidate = candidate.with_relationship(relationship);
    }
    let envelope = WriteEnvelope::new(
        WriteActor::new(machine, EdgeActorClass::System),
        ClaimSource::Observed,
        WriteProvenance::new(rmpv::Value::from("machine output")).expect("provenance"),
        ClaimApprovalStatus::Proposed,
    );
    let transcript = vault
        .machine_claim_transcript(&target, &candidate, &envelope)
        .expect("machine transcript");
    let proof = MachineWriteSignature {
        public_key: signing.verifying_key().to_bytes(),
        signature: signing.sign(&transcript).to_bytes(),
    };
    let signed = envelope.with_machine_signature(proof);
    vault
        .batch()
        .claim_candidate(&target, candidate, &signed, at(now), now)
        .commit()
        .expect("machine birth");
}

fn put_successor(
    vault: &Vault,
    owner: EntityId,
    subject: EntityId,
    target: EntityId,
    text: &str,
    now: u64,
) -> oneiron::Result<()> {
    let candidate = ClaimCandidate::new(
        "profile.note",
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
    );
    let envelope = WriteEnvelope::new(
        WriteActor::new(owner, EdgeActorClass::Human),
        ClaimSource::UserStated,
        WriteProvenance::new(rmpv::Value::from("person")).expect("provenance"),
        ClaimApprovalStatus::Auto,
    );
    vault
        .batch()
        .claim_candidate(&target, candidate, &envelope, at(now), now)
        .commit()
}

fn seed_grants(
    vault: &Vault,
    member: EntityId,
    co_owner: EntityId,
    now: u64,
) -> (SyncSelector, SyncSelector) {
    let scope = own_device_residence_scope();
    let member_grant_id = EntityId::now();
    let mut member_grant = FederationGrant::new(
        scope,
        member,
        FederationGrantRole::Member,
        FederationGrantPreset::Member,
    );
    member_grant.authority_scope = read_authority();
    put_selector_test_federation_grant(vault, &member_grant_id, &member_grant, now)
        .expect("the member grant");
    let co_grant_id = EntityId::now();
    let mut co_grant = FederationGrant::new(
        scope,
        co_owner,
        FederationGrantRole::Owner,
        FederationGrantPreset::Owner,
    );
    co_grant.authority_scope = read_authority();
    put_selector_test_federation_grant(vault, &co_grant_id, &co_grant, now)
        .expect("the co-owner grant");
    (
        SyncSelector::new(
            member_grant_id,
            member,
            SyncSelectorWorld::All,
            vec![],
            vec![],
        ),
        SyncSelector::new(
            co_grant_id,
            co_owner,
            SyncSelectorWorld::All,
            vec![],
            vec![],
        ),
    )
}

async fn serve(vault: Arc<Vault>, dir: tempfile::TempDir) -> Fixture {
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
    Fixture {
        task,
        url,
        _dir: dir,
        server,
    }
}

async fn fixture_private() -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault"));
    let now = vault.now_recorded_at();
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let member = EntityId::now();
    let co_owner = EntityId::now();
    let subject = EntityId::now();
    let body = person_body();
    vault
        .put_entity(&member, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("a member PERSON");
    vault
        .put_entity(&co_owner, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("a co-owner PERSON");
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("the claim subject");
    let machine = EntityId::now();
    vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(now), now, b"machine")
        .expect("a MACHINE");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[226; 32]);
    enroll_machine(&vault, &issuer, machine, &signing);
    let target = EntityId::now();
    seed_machine_birth(
        &vault,
        BirthSpec {
            machine,
            signing,
            subject,
            target,
            text: format!("a private machine note {PRIVATE_WORD}"),
            scope: Some(rmpv::Value::Map(vec![(
                rmpv::Value::from("sensitivity"),
                rmpv::Value::from("private"),
            )])),
            relationship: None,
            now,
        },
    );
    let owner = vault.ensure_embedded_owner_actor().expect("vault owner");
    bind_host_owner(&vault, &issuer, owner).expect("owner binding");
    let successor_refusal = put_successor(
        &vault,
        owner,
        subject,
        target,
        "a public successor note",
        now,
    )
    .err()
    .map(|error| error.to_string());
    let (member_selector, co_owner_selector) = seed_grants(&vault, member, co_owner, now);
    let key = WindowKey::from_timestamp(now).as_str().to_owned();
    let fixture = serve(vault, dir).await;
    Seeded {
        fixture,
        key,
        member_selector,
        co_owner_selector,
        member,
        co_owner,
        target,
        successor_refusal,
    }
}

async fn fixture_relationship() -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault"));
    let now = vault.now_recorded_at();
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let member = EntityId::now();
    let co_owner = EntityId::now();
    let subject = EntityId::now();
    let relationship = EntityId::now();
    let body = person_body();
    vault
        .put_entity(&member, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("a member PERSON");
    vault
        .put_entity(&co_owner, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("a co-owner PERSON");
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("the claim subject");
    vault
        .put_entity(
            &relationship,
            ENTITY_TYPE_RELATIONSHIP,
            at(now),
            now,
            b"relationship",
        )
        .expect("a relationship");
    let machine = EntityId::now();
    vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(now), now, b"machine")
        .expect("a MACHINE");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[226; 32]);
    enroll_machine(&vault, &issuer, machine, &signing);
    let target = EntityId::now();
    seed_machine_birth(
        &vault,
        BirthSpec {
            machine,
            signing,
            subject,
            target,
            text: format!("a relationship machine note {REL_WORD}"),
            scope: None,
            relationship: Some(relationship),
            now,
        },
    );
    let owner = vault.ensure_embedded_owner_actor().expect("vault owner");
    bind_host_owner(&vault, &issuer, owner).expect("owner binding");
    put_successor(
        &vault,
        owner,
        subject,
        target,
        "a public successor note",
        now,
    )
    .expect("FIXTURE: the successor that drops the label lands");
    let (member_selector, co_owner_selector) = seed_grants(&vault, member, co_owner, now);
    let key = WindowKey::from_timestamp(now).as_str().to_owned();
    let fixture = serve(vault, dir).await;
    Seeded {
        fixture,
        key,
        member_selector,
        co_owner_selector,
        member,
        co_owner,
        target,
        successor_refusal: None,
    }
}

async fn fixture_public() -> Seeded {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault"));
    let now = vault.now_recorded_at();
    let issuer = HostSlipIssuer::from_secret(SECRET.as_bytes()).expect("host issuer");
    vault.ensure_host_root_slip(&issuer).expect("host root");
    let member = EntityId::now();
    let co_owner = EntityId::now();
    let subject = EntityId::now();
    let body = person_body();
    vault
        .put_entity(&member, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("a member PERSON");
    vault
        .put_entity(&co_owner, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("a co-owner PERSON");
    vault
        .put_entity(&subject, ENTITY_TYPE_PERSON, at(now), now, &body)
        .expect("the claim subject");
    let machine = EntityId::now();
    vault
        .put_entity(&machine, ENTITY_TYPE_MACHINE, at(now), now, b"machine")
        .expect("a MACHINE");
    let signing = ed25519_dalek::SigningKey::from_bytes(&[226; 32]);
    enroll_machine(&vault, &issuer, machine, &signing);
    let target = EntityId::now();
    seed_machine_birth(
        &vault,
        BirthSpec {
            machine,
            signing,
            subject,
            target,
            text: "a public machine note".to_owned(),
            scope: None,
            relationship: None,
            now,
        },
    );
    let owner = vault.ensure_embedded_owner_actor().expect("vault owner");
    bind_host_owner(&vault, &issuer, owner).expect("owner binding");
    put_successor(
        &vault,
        owner,
        subject,
        target,
        "a public successor note",
        now,
    )
    .expect("FIXTURE: the public successor lands");
    let (member_selector, co_owner_selector) = seed_grants(&vault, member, co_owner, now);
    let key = WindowKey::from_timestamp(now).as_str().to_owned();
    let fixture = serve(vault, dir).await;
    Seeded {
        fixture,
        key,
        member_selector,
        co_owner_selector,
        member,
        co_owner,
        target,
        successor_refusal: None,
    }
}

/// The ruling's first case cannot be written: a public same-id successor of a
/// private machine birth is refused as a restamp (a CLAIM's sensitivity is
/// fixed at birth, `record_scope/stamping.rs`), and T stays the private
/// birth. The member then reads no row of it: its page is refused as not
/// found and no reply holds the secret word. T stays a Proposed birth, so the
/// target admission alone refuses it: the page gate's stamped-claim arm is
/// defence in depth here; test 2 is the reachable leak.
#[tokio::test]
async fn a_private_machine_birth_takes_no_public_successor_and_serves_no_member_page() {
    let seeded = fixture_private().await;
    let refusal = seeded
        .successor_refusal
        .as_deref()
        .expect("the public successor of a private machine birth is refused");
    assert!(
        refusal.contains("record scope restamp refused"),
        "the public successor is refused as a restamp, not for another reason: {refusal}"
    );
    let vault = seeded.fixture.server.vault();
    let live = vault
        .get_claim(&seeded.target)
        .expect("claim read")
        .expect("T is stored");
    assert!(
        live.scope.is_some(),
        "T keeps the private birth's sensitivity stamp after the refusal"
    );
    assert!(
        live.value
            .as_str()
            .is_some_and(|value| value.contains(PRIVATE_WORD)),
        "T is still the private machine birth"
    );
    let mut socket = connect(&seeded).await;
    let member_credential = credential(&seeded.fixture.server, seeded.member);
    bind(&mut socket, &member_credential, 5).await;
    match history_page(&mut socket, &seeded.member_selector, seeded.target, 11).await {
        Err(error) => {
            assert_eq!(
                error.get("code").and_then(|code| code.as_str()),
                Some("NOT_FOUND"),
                "LEAK: the member refusal is not found"
            );
            assert!(
                !format!("{error}").contains(PRIVATE_WORD),
                "LEAK: the member refusal carries the secret word"
            );
        }
        Ok(page) => {
            let leaked = page_contains_word(&page, PRIVATE_WORD);
            panic!("LEAK: the member history served (secret present: {leaked}): {page}");
        }
    }
}

#[tokio::test]
async fn an_outside_member_gets_no_history_after_a_dropped_relationship_label() {
    let seeded = fixture_relationship().await;
    let target_hex = seeded.target.to_hex();
    let vault = seeded.fixture.server.vault();
    let live = vault
        .get_claim(&seeded.target)
        .expect("claim read")
        .expect("T is stored");
    assert!(
        live.scope.is_none(),
        "FIXTURE: the successor carries no sensitivity stamp"
    );
    assert!(
        live.rel.is_none(),
        "FIXTURE: the successor drops the relationship label"
    );
    assert!(
        live.value
            .as_str()
            .is_some_and(|value| !value.contains(REL_WORD)),
        "FIXTURE: the successor carries no secret word"
    );
    let mut co_socket = connect(&seeded).await;
    let co_credential = credential(&seeded.fixture.server, seeded.co_owner);
    bind(&mut co_socket, &co_credential, 5).await;
    let co_page = history_page(&mut co_socket, &seeded.co_owner_selector, seeded.target, 11)
        .await
        .expect("FIXTURE: the co-owner history serves");
    assert_eq!(
        co_page.get("target").and_then(|target| target.as_str()),
        Some(target_hex.as_str()),
        "FIXTURE: the co-owner page targets T"
    );
    assert_eq!(
        co_page.get("pending").and_then(|pending| pending.as_bool()),
        Some(false),
        "FIXTURE: the co-owner history resolves"
    );
    let co_rows = co_page
        .get("rows")
        .and_then(|rows| rows.as_array())
        .expect("FIXTURE: the co-owner rows decode");
    assert!(
        !co_rows.is_empty(),
        "FIXTURE: the co-owner history holds rows"
    );
    assert!(
        page_contains_word(&co_page, REL_WORD),
        "FIXTURE: the co-owner history holds the secret word"
    );
    let mut socket = connect(&seeded).await;
    let member_credential = credential(&seeded.fixture.server, seeded.member);
    bind(&mut socket, &member_credential, 5).await;
    let doc = fetch_for(&seeded.member_selector, seeded.key.as_str(), &mut socket).await;
    assert!(
        doc.get_map("entities").get(target_hex.as_str()).is_some(),
        "FIXTURE: the member fetch carries T"
    );
    match history_page(&mut socket, &seeded.member_selector, seeded.target, 11).await {
        Err(error) => {
            assert_eq!(
                error.get("code").and_then(|code| code.as_str()),
                Some("NOT_FOUND"),
                "LEAK: the member refusal is not found"
            );
            assert!(
                !format!("{error}").contains(REL_WORD),
                "LEAK: the member refusal carries the secret word"
            );
        }
        Ok(page) => {
            let leaked = page_contains_word(&page, REL_WORD);
            panic!("LEAK: the member history served (secret present: {leaked}): {page}");
        }
    }
}

/// The owner guard: a co-Owner (an Owner-role grant, the selector's Owner set)
/// reads every control, the relationship-labelled birth included, and is
/// served the whole history.
#[tokio::test]
async fn the_co_owner_gets_the_history_after_a_dropped_relationship_label() {
    let seeded = fixture_relationship().await;
    let target_hex = seeded.target.to_hex();
    let mut socket = connect(&seeded).await;
    let co_credential = credential(&seeded.fixture.server, seeded.co_owner);
    bind(&mut socket, &co_credential, 5).await;
    let page = history_page(&mut socket, &seeded.co_owner_selector, seeded.target, 11)
        .await
        .expect("the co-owner history serves");
    assert_eq!(
        page.get("target").and_then(|target| target.as_str()),
        Some(target_hex.as_str()),
        "the co-owner page targets T"
    );
    assert_eq!(
        page.get("pending").and_then(|pending| pending.as_bool()),
        Some(false),
        "the co-owner history resolves"
    );
    let rows = page
        .get("rows")
        .and_then(|rows| rows.as_array())
        .expect("the co-owner rows decode");
    assert!(!rows.is_empty(), "the co-owner history holds rows");
    assert!(
        page_contains_word(&page, REL_WORD),
        "the co-owner history holds the labelled birth's word"
    );
}

#[tokio::test]
async fn a_member_reading_every_control_gets_the_history() {
    let seeded = fixture_public().await;
    let target_hex = seeded.target.to_hex();
    let mut socket = connect(&seeded).await;
    let member_credential = credential(&seeded.fixture.server, seeded.member);
    bind(&mut socket, &member_credential, 5).await;
    let doc = fetch_for(&seeded.member_selector, seeded.key.as_str(), &mut socket).await;
    assert!(
        doc.get_map("entities").get(target_hex.as_str()).is_some(),
        "FIXTURE: the member fetch carries the public T"
    );
    let page = history_page(&mut socket, &seeded.member_selector, seeded.target, 11)
        .await
        .expect("the member history serves");
    assert_eq!(
        page.get("target").and_then(|target| target.as_str()),
        Some(target_hex.as_str()),
        "the member page targets T"
    );
    assert_eq!(
        page.get("pending").and_then(|pending| pending.as_bool()),
        Some(false),
        "the member history resolves"
    );
    let rows = page
        .get("rows")
        .and_then(|rows| rows.as_array())
        .expect("the member rows decode");
    assert!(!rows.is_empty(), "the member history holds rows");
}
