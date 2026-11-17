//! Room standing on the context-pack route (L5-02 PR 3 finding 3).
//!
//! Naming a room lifts the conversation home only for a reader that stands
//! in it: a member, a Ready join, a leader chat actor, or the host. An
//! outside reader that can read the room's record but is not in the room
//! reads no stamped claim through it. Unstamped and `public` claims still
//! read. The outside reader's stamped-claim assertions are red on the base
//! (a readable room lifted the home for any reader) and green on the head.
//!
//! Fixture: `context_pack_conversation_home.rs`'s host (four claims about
//! one PERSON, an outside precleared contact's read-only slip that is not a
//! member), with a room seating one member whose own contact is precleared
//! too and not the owner, so the room's audience admits every claim and the
//! home alone decides. Deterministic:
//! in-process vault and router (`oneshot`, no TCP ports, no sleeps, no
//! models, no embedder).
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test context_pack_room_standing`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof_challenge};
use oneiron::conversation::{ConversationBody, ConversationKind};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const CONTEXT_PACK: &str = "/v1/core/context-pack";
/// When the seeded claims and their subject were learned and hold.
const LEARNED_AT: u64 = 1_780_000_000;
/// The word every seeded claim holds, which no other row holds.
const SHARED_WORD: &str = "lanternwick";
/// The one word each seeded claim alone holds.
const UNSTAMPED_WORD: &str = "juniper";
const PUBLIC_WORD: &str = "sorrel";
const PRIVATE_WORD: &str = "wren";
const SENSITIVE_WORD: &str = "lark";
/// The seeded claims' predicate, which is not Tier A.
const PREDICATE: &str = "profile.note";

struct Host {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    outside_slip: CapabilitySlip,
    outside_token: String,
    outside_key: SigningKey,
    unstamped: EntityId,
    public: EntityId,
    private_stamped: EntityId,
    sensitive_stamped: EntityId,
    room: EntityId,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One seeded claim about `subject`, holding `text`, stamped `sensitivity`
/// when named, and indexed for text retrieval.
fn seed_claim(
    vault: &Vault,
    id: &EntityId,
    subject: EntityId,
    text: &str,
    sensitivity: Option<&str>,
) -> TestResult {
    let mut body = ClaimBody::new(
        PREDICATE,
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text),
        1.0,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )?;
    body.source = Some(ClaimSource::UserStated);
    if let Some(band) = sensitivity {
        body.scope = Some(rmpv::Value::Map(vec![(
            rmpv::Value::from("sensitivity"),
            rmpv::Value::from(band),
        )]));
    }
    vault.put_claim(
        id,
        &body,
        TimeRange {
            start: LEARNED_AT,
            end: LEARNED_AT,
        },
        LEARNED_AT,
    )?;
    vault.batch().text(id, &[("body", text)]).commit()?;
    Ok(())
}

impl Host {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        config.dimensions = 4;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let owner = vault.ensure_embedded_owner_actor()?;
        // One PERSON the four claims hang off, one more PERSON seating the
        // room, and one PERSON the outside contact's identity links to.
        let subject = EntityId::now();
        vault.put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"home clearance subject",
        )?;
        let other = EntityId::now();
        vault.put_entity(
            &other,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"room member",
        )?;
        let outside_person = EntityId::now();
        vault.put_entity(
            &outside_person,
            ENTITY_TYPE_PERSON,
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            LEARNED_AT,
            b"outside person",
        )?;
        // Four claims about one PERSON, each findable by the shared word and
        // its own word, written as the empty-beside-L2 fixture writes its
        // base claim.
        let unstamped = EntityId::from_bytes([0x51; 16])?;
        seed_claim(
            &vault,
            &unstamped,
            subject,
            &format!("{SHARED_WORD} {UNSTAMPED_WORD}"),
            None,
        )?;
        let public = EntityId::from_bytes([0x52; 16])?;
        seed_claim(
            &vault,
            &public,
            subject,
            &format!("{SHARED_WORD} {PUBLIC_WORD}"),
            Some("public"),
        )?;
        let private_stamped = EntityId::from_bytes([0x53; 16])?;
        seed_claim(
            &vault,
            &private_stamped,
            subject,
            &format!("{SHARED_WORD} {PRIVATE_WORD}"),
            Some("private"),
        )?;
        let sensitive_stamped = EntityId::from_bytes([0x54; 16])?;
        seed_claim(
            &vault,
            &sensitive_stamped,
            subject,
            &format!("{SHARED_WORD} {SENSITIVE_WORD}"),
            Some("sensitive"),
        )?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("context-pack-room-standing".into()),
                ..Default::default()
            },
        )?);
        let issuer = vault.load_host_slip_issuer()?;
        let owner_slip = vault.ensure_host_root_slip(&issuer)?;
        let owner_token = owner_slip.to_token()?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        // A room of this vault seating one member, a contact cleared for the
        // vault's full scope (below), and not the owner. The owner's host
        // credential names no PERSON in a room, so a seated owner meets as an
        // unknown party and clamps every reader's pack to the public claim.
        // With only cleared parties in the room, the home alone decides.
        let room = EntityId::now();
        vault.create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![other],
                ..Default::default()
            },
            WriteActor::new(owner, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )?;
        // The outside reader's contact and the room member's, each About its
        // PERSON alone and cleared for the vault's full scope, so the
        // audience clamp admits the sensitive claim on main.
        let contact = EntityId::now();
        vault.create_counterparty_contact(
            &contact,
            &CounterpartyContactRecord::public(
                outside_person,
                "outside@example.com",
                vault.now_recorded_at(),
            )?,
        )?;
        let member_contact = EntityId::now();
        vault.create_counterparty_contact(
            &member_contact,
            &CounterpartyContactRecord::public(
                other,
                "member@example.com",
                vault.now_recorded_at(),
            )?,
        )?;
        let proof = vault
            .memory(owner, EdgeActorClass::Human)
            .embedded_owner("vault.disclosure.home.set")?;
        let _ = vault.preclear_contact_disclosure(
            &proof,
            "outside-reader",
            &[contact, member_contact],
            Scope::top(),
        )?;
        // The outside reader's delegated credential: read-only, so not
        // owner-grade, and not one of the vault's own agents.
        let outside_key = SigningKey::from_bytes(&[0x66; 32]);
        let mut scope = Scope::top();
        scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
        let mut claims = owner_slip.claims.clone();
        claims.parent_id = None;
        claims.holder_ref = contact.to_hex();
        claims.binding_key = outside_key.verifying_key().to_bytes();
        claims.actor_class = Some("human".to_owned());
        claims.scope = scope;
        claims.slip_id = [0x66; 32];
        let outside_slip = vault.mint_capability_slip(&issuer, claims)?;
        let outside_token = outside_slip.to_token()?;
        let app = build_app(server);
        Ok(Self {
            _dir: dir,
            vault,
            app,
            issuer,
            owner_slip,
            owner_token,
            outside_slip,
            outside_token,
            outside_key,
            unstamped,
            public,
            private_stamped,
            sensitive_stamped,
            room,
        })
    }

    fn owner_binding(&self) -> TestResult<String> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let proof = self
            .issuer
            .binding_proof(&self.owner_slip, challenge.as_bytes())?;
        Ok(json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&proof)}).to_string())
    }

    fn outside_binding(&self) -> TestResult<String> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let transcript = self.outside_slip.binding_transcript(&challenge)?;
        let signature = self.outside_key.sign(&transcript).to_bytes();
        Ok(
            json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)})
                .to_string(),
        )
    }

    async fn post_as_owner(&self, path: &str, body: Value) -> TestResult<(StatusCode, Value)> {
        let request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.owner_token))
            .header("x-oneiron-binding", self.owner_binding()?)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{path} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Ok((status, answer))
    }

    async fn post_as_outside(&self, path: &str, body: Value) -> TestResult<(StatusCode, Value)> {
        let request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.outside_token))
            .header("x-oneiron-binding", self.outside_binding()?)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let answer: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            panic!(
                "{path} answered no JSON: {}",
                String::from_utf8_lossy(&bytes)
            )
        });
        Ok((status, answer))
    }
}

fn result_ids(pack: &Value) -> Vec<String> {
    pack["results"]
        .as_array()
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn an_outside_reader_naming_a_room_it_is_not_in_reads_no_stamped_claim() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let (status, pack) = host
            .post_as_outside(
                CONTEXT_PACK,
                json!({
                    "query": SHARED_WORD,
                    "limit": 10,
                    "conversation_id": host.room.to_hex(),
                }),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "naming a readable room answers 200 for the outside reader: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "the outside reader naming a room it is not in still reads the unstamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "the outside reader naming a room it is not in still reads the public claim: {pack}"
        );
        assert!(
            !ids.contains(&host.private_stamped.to_hex()),
            "the outside reader naming a room it is not in reads no private stamped claim: {pack}"
        );
        assert!(
            !ids.contains(&host.sensitive_stamped.to_hex()),
            "the outside reader naming a room it is not in reads no sensitive stamped claim: {pack}"
        );
        Ok(())
    })
}

#[test]
fn the_owner_naming_the_room_reads_every_claim() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let (status, pack) = host
            .post_as_owner(
                CONTEXT_PACK,
                json!({
                    "query": SHARED_WORD,
                    "limit": 10,
                    "conversation_id": host.room.to_hex(),
                }),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "naming the room answers 200 for the owner: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "the owner naming the room reads the unstamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "the owner naming the room reads the public claim: {pack}"
        );
        assert!(
            ids.contains(&host.private_stamped.to_hex()),
            "the owner naming the room reads the private stamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.sensitive_stamped.to_hex()),
            "the owner naming the room reads the sensitive stamped claim: {pack}"
        );
        Ok(())
    })
}
