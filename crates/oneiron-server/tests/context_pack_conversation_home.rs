//! Conversation-home clearance on the context-pack route (DEC-0006 #home-clearance).
//!
//! A CLAIM stamped with any band but `public` is read only in a conversation
//! homed in its own vault, unless the owner granted that home a clearance at
//! or above the claim's band. Unstamped and `public` claims stay visible; the
//! audience clamp still applies on top.
//!
//! Six cases drive the real route with real credentials (on a profiled
//! install, as a serving start enrols it). Deterministic: in-process vault
//! and router (`oneshot`, no TCP ports, no sleeps, no models, no embedder).
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --features oneiron/test-support --test context_pack_conversation_home`.

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
const HOME_SET: &str = "/v1/core/facade/vault.disclosure.home.set";
const HOME_CLEAR: &str = "/v1/core/facade/vault.disclosure.home.clear";
/// Another vault's authority id, as the home rule names it.
const OTHER: [u8; 32] = [0x42; 32];
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
                auth_secret: Some("context-pack-conversation-home".into()),
                ..Default::default()
            },
        )?);
        let issuer = vault.load_host_slip_issuer()?;
        let owner_slip = vault.ensure_host_root_slip(&issuer)?;
        let owner_token = owner_slip.to_token()?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        // A room of this vault seating the owner and one more member.
        let room = EntityId::now();
        vault.create_conversation(
            room,
            &ConversationBody {
                kind: ConversationKind::Group,
                member_ids: vec![owner, other],
                ..Default::default()
            },
            WriteActor::new(owner, EdgeActorClass::Human),
            vault.now_recorded_at(),
        )?;
        // The outside reader's contact, cleared for the vault's full scope,
        // so the audience clamp admits the sensitive claim on main.
        let contact = EntityId::now();
        vault.create_counterparty_contact(
            &contact,
            &CounterpartyContactRecord::public(
                outside_person,
                "outside@example.com",
                vault.now_recorded_at(),
            )?,
        )?;
        let proof = vault
            .memory(owner, EdgeActorClass::Human)
            .embedded_owner("vault.disclosure.home.set")?;
        let _ = vault.preclear_contact_disclosure(
            &proof,
            "outside-reader",
            &[contact],
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

    async fn home_set(&self, input: Value) -> TestResult<Value> {
        let (status, body) = self.post_as_owner(HOME_SET, input).await?;
        assert_eq!(status, StatusCode::OK, "{HOME_SET} answered {body}");
        Ok(body)
    }

    async fn home_clear(&self, input: Value) -> TestResult<Value> {
        let (status, body) = self.post_as_owner(HOME_CLEAR, input).await?;
        assert_eq!(status, StatusCode::OK, "{HOME_CLEAR} answered {body}");
        Ok(body)
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
fn a_pack_homed_in_another_vault_leaves_stamped_claims_out() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let home = hex(&OTHER);
        let (status, pack) = host
            .post_as_owner(
                CONTEXT_PACK,
                json!({"query": SHARED_WORD, "limit": 10, "conversation_home": home}),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "a pack homed in another vault answers 200 for the owner: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "the owner homed elsewhere still reads the unstamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "the owner homed elsewhere still reads the public claim: {pack}"
        );
        assert!(
            !ids.contains(&host.private_stamped.to_hex()),
            "the owner homed elsewhere does not read the private stamped claim: {pack}"
        );
        assert!(
            !ids.contains(&host.sensitive_stamped.to_hex()),
            "the owner homed elsewhere does not read the sensitive stamped claim: {pack}"
        );
        assert_eq!(
            pack["disclosure"]["home"],
            json!(home),
            "the pack names the home vault it was homed in: {pack}"
        );
        assert_eq!(
            pack["disclosure"]["mode"],
            json!("owner_alone"),
            "the owner alone homed elsewhere reads as owner_alone: {pack}"
        );
        Ok(())
    })
}

#[test]
fn the_owner_unnamed_is_homed_here() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let (status, pack) = host
            .post_as_owner(CONTEXT_PACK, json!({"query": SHARED_WORD, "limit": 10}))
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner with no home answers 200: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "the owner with no home reads the unstamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "the owner with no home reads the public claim: {pack}"
        );
        assert!(
            ids.contains(&host.private_stamped.to_hex()),
            "the owner with no home reads the private stamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.sensitive_stamped.to_hex()),
            "the owner with no home reads the sensitive stamped claim: {pack}"
        );
        Ok(())
    })
}

#[test]
fn a_room_of_this_vault_cannot_be_homed_elsewhere() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let home = hex(&OTHER);
        let (status, body) = host
            .post_as_owner(
                CONTEXT_PACK,
                json!({
                    "query": SHARED_WORD,
                    "limit": 10,
                    "conversation_id": host.room.to_hex(),
                    "conversation_home": home,
                }),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a room of this vault homed elsewhere is refused: {body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or("");
        assert!(
            message.contains("a conversation of this vault is homed in this vault"),
            "the refusal names the room home rule, got: {body}"
        );
        Ok(())
    })
}

#[test]
fn the_owner_sets_a_home_clearance_through_its_verb() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let home = hex(&OTHER);
        let set = host
            .home_set(json!({"home_vault_id": home, "band": "sensitive"}))
            .await?;
        assert_eq!(
            set["band"],
            json!("sensitive"),
            "the set verb stores the sensitive band: {set}"
        );
        let (status, pack) = host
            .post_as_owner(
                CONTEXT_PACK,
                json!({"query": SHARED_WORD, "limit": 10, "conversation_home": home}),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "a cleared home answers 200 for the owner: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "the owner homed in the cleared vault reads the unstamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "the owner homed in the cleared vault reads the public claim: {pack}"
        );
        assert!(
            ids.contains(&host.private_stamped.to_hex()),
            "the owner homed in the cleared vault reads the private stamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.sensitive_stamped.to_hex()),
            "the owner homed in the cleared vault reads the sensitive stamped claim: {pack}"
        );
        let cleared = host.home_clear(json!({"home_vault_id": home})).await?;
        assert!(
            cleared["band"].is_null(),
            "the clear verb removes the band: {cleared}"
        );
        let (status, pack) = host
            .post_as_owner(
                CONTEXT_PACK,
                json!({"query": SHARED_WORD, "limit": 10, "conversation_home": home}),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "a revoked home answers 200 for the owner: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "the owner homed in the revoked vault still reads the unstamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "the owner homed in the revoked vault still reads the public claim: {pack}"
        );
        assert!(
            !ids.contains(&host.private_stamped.to_hex()),
            "the owner homed in the revoked vault does not read the private stamped claim: {pack}"
        );
        assert!(
            !ids.contains(&host.sensitive_stamped.to_hex()),
            "the owner homed in the revoked vault does not read the sensitive stamped claim: {pack}"
        );
        Ok(())
    })
}

#[test]
fn an_outside_reader_unnamed_is_homed_elsewhere() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let (status, pack) = host
            .post_as_outside(CONTEXT_PACK, json!({"query": SHARED_WORD, "limit": 10}))
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "an outside reader with no home answers 200: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "an outside reader homed in the unnamed vault still reads the unstamped claim: {pack}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "an outside reader homed in the unnamed vault still reads the public claim: {pack}"
        );
        assert!(
            !ids.contains(&host.private_stamped.to_hex()),
            "an outside reader homed in the unnamed vault does not read the private stamped claim: {pack}"
        );
        assert!(
            !ids.contains(&host.sensitive_stamped.to_hex()),
            "an outside reader homed in the unnamed vault does not read the sensitive stamped claim: {pack}"
        );
        Ok(())
    })
}

#[test]
fn an_outside_reader_cannot_name_a_cleared_home() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let home = hex(&OTHER);
        host.home_set(json!({"home_vault_id": home, "band": "sensitive"}))
            .await?;
        let (status, body) = host
            .post_as_outside(
                CONTEXT_PACK,
                json!({"query": SHARED_WORD, "limit": 10, "conversation_home": home}),
            )
            .await?;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an outside reader naming a cleared home is refused: {body}"
        );
        assert!(
            body.to_string().contains("conversation_home"),
            "the refusal names the conversation_home control, got: {body}"
        );
        let (status, pack) = host
            .post_as_outside(CONTEXT_PACK, json!({"query": SHARED_WORD, "limit": 10}))
            .await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "the outside reader unnamed still answers 200: {pack}"
        );
        let ids = result_ids(&pack);
        assert!(
            !ids.contains(&host.private_stamped.to_hex()),
            "another home's clearance does not reach the unnamed outside reader (private): {pack}"
        );
        assert!(
            !ids.contains(&host.sensitive_stamped.to_hex()),
            "another home's clearance does not reach the unnamed outside reader (sensitive): {pack}"
        );
        Ok(())
    })
}
