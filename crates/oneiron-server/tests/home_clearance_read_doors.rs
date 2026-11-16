//! Home clearance on the read doors (L5-02 PR 3, RULING SECREAD-HOME-READ-DOORS = B).
//!
//! A reader that is neither the vault's owner nor one of its own agents
//! reading on its own reads no claim stamped `sensitivity` private or
//! sensitive on any read door, unless it reads inside a room of this vault.
//! Unstamped and `public` claims still read. The owner reads all of them.
//! Each outside-reader assertion below is red on the base (the precleared
//! contact's delegated read slip read the stamped claims there) and green on
//! the head. The vault's own agent reading on its own still reads the stamped
//! claims; the same slip in another key's hand does not.
//!
//! One test per door over the conversation-home fixture's four claims about
//! one PERSON (unstamped, public, private, sensitive), each holding the shared
//! word and its own word, each test with the owner's same request as a
//! control. Vector search is skipped: the fixture sets `embedding_model =
//! None`, so no vector can be written and the door cannot return these claims
//! (see NOTES.md). Deterministic: in-process vault and router (`oneshot`, no
//! TCP ports, no sleeps, no models, no embedder).
//!
//! Run with: RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test home_clearance_read_doors

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
use oneiron::agent_def::{AgentCeiling, AgentDefinition, AgentScope};
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, SlipCaveat, holder_proof_challenge,
};
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject, EntityId,
    TimeRange, Vault, VaultConfig,
};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEXT_SEARCH: &str = "/api/search/text";
const HYDRATE: &str = "/v1/core/hydrate";
const RECALL: &str = "/v1/core/facade/vault.recall";
const MEMORY_REASON: &str = "/v1/companion/memory/reason";
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
    outside_person_slip: CapabilitySlip,
    outside_person_token: String,
    outside_person_key: SigningKey,
    agent_slip: CapabilitySlip,
    agent_token: String,
    agent_key: SigningKey,
    transferred_slip: CapabilitySlip,
    transferred_token: String,
    transferred_key: SigningKey,
    unstamped: EntityId,
    public: EntityId,
    private_stamped: EntityId,
    sensitive_stamped: EntityId,
}

/// The vault's own agent credential and the same slip handed to another key.
struct AgentSlips {
    slip: CapabilitySlip,
    token: String,
    key: SigningKey,
    transferred_slip: CapabilitySlip,
    transferred_token: String,
    transferred_key: SigningKey,
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

/// The live AGENT_DEF row the owner creates for the vault's own agent, as the
/// served-batch conformance fixture creates its author.
fn owner_agent_definition(name: &str) -> AgentDefinition {
    AgentDefinition::new(
        name,
        "home clearance own-agent fixture",
        "1",
        Some("Count carefully.\n".to_owned()),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        None,
        AgentScope::Base,
        AgentCeiling::Proposed,
        None,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
        ClaimSource::UserStated,
        1.0,
        false,
        true,
        rmpv::Value::Map(vec![("definedVia".into(), "define_agent".into())]),
        None,
        true,
        None,
    )
}

/// A read-only slip for `author`, one of the vault's own agents, held as
/// class `agent`, and the same slip handed to another key.
fn mint_agent_slips(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    owner_slip: &CapabilitySlip,
    author: &EntityId,
) -> TestResult<AgentSlips> {
    let key = SigningKey::from_bytes(&[0x67; 32]);
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    let mut claims = owner_slip.claims.clone();
    claims.parent_id = None;
    claims.holder_ref = author.to_hex();
    claims.binding_key = key.verifying_key().to_bytes();
    claims.actor_class = Some("agent".to_owned());
    claims.scope = scope;
    claims.slip_id = [0x67; 32];
    let slip = vault.mint_capability_slip(issuer, claims)?;
    let token = slip.to_token()?;
    // The same slip handed to another key: whoever proves it now is not the
    // agent reading on its own.
    let transferred_key = SigningKey::from_bytes(&[0x68; 32]);
    let mut transferred_slip = slip.clone();
    transferred_slip.attenuate_to(
        SlipCaveat::default(),
        &key,
        transferred_key.verifying_key().to_bytes(),
    )?;
    let transferred_token = transferred_slip.to_token()?;
    Ok(AgentSlips {
        slip,
        token,
        key,
        transferred_slip,
        transferred_token,
        transferred_key,
    })
}

impl Host {
    fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = VaultConfig::device();
        config.embedding_model = None;
        config.dimensions = 4;
        let vault = Arc::new(Vault::open_owned(dir.path(), config)?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::new()));
        let owner = vault.ensure_embedded_owner_actor()?;
        // One PERSON the four claims hang off, and one PERSON the outside
        // contact's identity links to.
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
                auth_secret: Some("home-clearance-read-doors".into()),
                ..Default::default()
            },
        )?);
        let issuer = vault.load_host_slip_issuer()?;
        let owner_slip = vault.ensure_host_root_slip(&issuer)?;
        let owner_token = owner_slip.to_token()?;
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
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
        // The vault's own agent: a live AGENT_DEF row the owner creates, so
        // the lane reads its holder as one of the vault's own agents.
        let author = EntityId::from_bytes([0x70; 16])?;
        vault.create_agent_definition_as(
            &proof,
            &author,
            &owner_agent_definition("home-clearance.reader"),
            TimeRange {
                start: LEARNED_AT,
                end: LEARNED_AT,
            },
            vault.now_recorded_at(),
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
        let outside_slip = vault.mint_capability_slip(&issuer, claims.clone())?;
        let outside_token = outside_slip.to_token()?;
        // The same read-only credential held by the contact's PERSON: the
        // facade binds a `human` caller only to a PERSON, never to a
        // COUNTERPARTY_CONTACT, so recall reads as this outside reader.
        let outside_person_key = SigningKey::from_bytes(&[0x69; 32]);
        claims.holder_ref = outside_person.to_hex();
        claims.binding_key = outside_person_key.verifying_key().to_bytes();
        claims.slip_id = [0x69; 32];
        let outside_person_slip = vault.mint_capability_slip(&issuer, claims)?;
        let outside_person_token = outside_person_slip.to_token()?;
        let agent = mint_agent_slips(&vault, &issuer, &owner_slip, &author)?;
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
            outside_person_slip,
            outside_person_token,
            outside_person_key,
            agent_slip: agent.slip,
            agent_token: agent.token,
            agent_key: agent.key,
            transferred_slip: agent.transferred_slip,
            transferred_token: agent.transferred_token,
            transferred_key: agent.transferred_key,
            unstamped,
            public,
            private_stamped,
            sensitive_stamped,
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

    fn holder_binding(&self, slip: &CapabilitySlip, key: &SigningKey) -> TestResult<String> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let transcript = slip.binding_transcript(&challenge)?;
        let signature = key.sign(&transcript).to_bytes();
        Ok(
            json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&signature)})
                .to_string(),
        )
    }

    fn agent_binding(&self) -> TestResult<String> {
        self.holder_binding(&self.agent_slip, &self.agent_key)
    }

    fn transferred_binding(&self) -> TestResult<String> {
        self.holder_binding(&self.transferred_slip, &self.transferred_key)
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

    /// A POST as the outside reader's PERSON-held credential.
    async fn post_as_outside_person(
        &self,
        path: &str,
        body: Value,
    ) -> TestResult<(StatusCode, Value)> {
        let binding = self.holder_binding(&self.outside_person_slip, &self.outside_person_key)?;
        let request = Request::post(path)
            .header(
                "authorization",
                format!("Bearer {}", self.outside_person_token),
            )
            .header("x-oneiron-binding", binding)
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

    async fn get_as(
        &self,
        token: &str,
        binding: &str,
        path: &str,
    ) -> TestResult<(StatusCode, Value)> {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", binding)
            .body(Body::empty())?;
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

    async fn get_as_owner(&self, path: &str) -> TestResult<(StatusCode, Value)> {
        let binding = self.owner_binding()?;
        self.get_as(&self.owner_token, &binding, path).await
    }

    async fn get_as_outside(&self, path: &str) -> TestResult<(StatusCode, Value)> {
        let binding = self.outside_binding()?;
        self.get_as(&self.outside_token, &binding, path).await
    }

    async fn get_as_agent(&self, path: &str) -> TestResult<(StatusCode, Value)> {
        let binding = self.agent_binding()?;
        self.get_as(&self.agent_token, &binding, path).await
    }

    async fn get_as_transferred(&self, path: &str) -> TestResult<(StatusCode, Value)> {
        let binding = self.transferred_binding()?;
        self.get_as(&self.transferred_token, &binding, path).await
    }

    /// The short name of `id`'s live short reference: the part that names the
    /// row in recall items and reason sources.
    fn short_name_of(&self, id: &EntityId) -> TestResult<String> {
        Ok(short_name(&oneiron::retrieval_depth::short_ref_or_hex(
            &self.vault,
            id,
        )?)
        .to_owned())
    }
}

/// The hex ids of a text search page, in order.
fn search_ids(answer: &Value) -> Vec<String> {
    answer["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["id"].as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The short name of a `name:hash[@revision]` reference (or a bare hex id):
/// the part that names the row, whatever hash or revision rides with it.
fn short_name(reference: &str) -> &str {
    reference
        .split('@')
        .next()
        .unwrap_or(reference)
        .split(':')
        .next()
        .unwrap_or(reference)
}

/// The short names of a recall pack's items, in order.
fn recall_names(pack: &Value) -> Vec<String> {
    pack["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    item["short_id"]
                        .as_str()
                        .map(|id| short_name(id).to_owned())
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The value texts of a recall pack's items, joined.
fn recall_text(pack: &Value) -> String {
    pack["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item["value_text"].as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })
        .unwrap_or_default()
}

/// The short names of a reason answer's cited sources, in order.
fn reason_names(answer: &Value) -> Vec<String> {
    answer["sources"]
        .as_array()
        .map(|sources| {
            sources
                .iter()
                .filter_map(|source| source.as_str().map(|id| short_name(id).to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn outside_text_search_leaves_stamped_claims_out() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let path = format!("{TEXT_SEARCH}?query={SHARED_WORD}&limit=10");
        let (status, answer) = host.get_as_outside(&path).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "text search answers 200 for the outside reader: {answer}"
        );
        let ids = search_ids(&answer);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "text search serves the outside reader the unstamped claim: {answer}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "text search serves the outside reader the public claim: {answer}"
        );
        assert!(
            !ids.contains(&host.private_stamped.to_hex()),
            "text search withholds the private stamped claim from the outside reader: {answer}"
        );
        assert!(
            !ids.contains(&host.sensitive_stamped.to_hex()),
            "text search withholds the sensitive stamped claim from the outside reader: {answer}"
        );
        let (status, answer) = host.get_as_owner(&path).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "text search answers 200 for the owner: {answer}"
        );
        let ids = search_ids(&answer);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "text search serves the owner the unstamped claim: {answer}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "text search serves the owner the public claim: {answer}"
        );
        assert!(
            ids.contains(&host.private_stamped.to_hex()),
            "text search serves the owner the private stamped claim: {answer}"
        );
        assert!(
            ids.contains(&host.sensitive_stamped.to_hex()),
            "text search serves the owner the sensitive stamped claim: {answer}"
        );
        Ok(())
    })
}

#[test]
fn outside_hydrate_leaves_stamped_claims_out() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let refs = [
            (
                "unstamped",
                false,
                host.unstamped,
                oneiron::retrieval_depth::short_ref_or_hex(&host.vault, &host.unstamped)?,
            ),
            (
                "public",
                false,
                host.public,
                oneiron::retrieval_depth::short_ref_or_hex(&host.vault, &host.public)?,
            ),
            (
                "private stamped",
                true,
                host.private_stamped,
                oneiron::retrieval_depth::short_ref_or_hex(&host.vault, &host.private_stamped)?,
            ),
            (
                "sensitive stamped",
                true,
                host.sensitive_stamped,
                oneiron::retrieval_depth::short_ref_or_hex(&host.vault, &host.sensitive_stamped)?,
            ),
        ];
        // Each claim names whether the home withholds it from the outside
        // reader: the private and sensitive stamped claims (a name test
        // would also match "unstamped").
        for (name, withheld, id, reference) in &refs {
            let (status, answer) = host
                .post_as_outside(HYDRATE, json!({"ref": reference}))
                .await?;
            if *withheld {
                assert_eq!(
                    status,
                    StatusCode::NOT_FOUND,
                    "hydrate refuses the outside reader's {name} claim with 404: {answer}"
                );
            } else {
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "hydrate answers 200 for the outside reader's {name} claim: {answer}"
                );
                assert_eq!(
                    answer["id"].as_str().unwrap_or_default(),
                    id.to_hex(),
                    "hydrate serves the outside reader the {name} claim: {answer}"
                );
            }
            let (status, answer) = host
                .post_as_owner(HYDRATE, json!({"ref": reference}))
                .await?;
            assert_eq!(
                status,
                StatusCode::OK,
                "hydrate answers 200 for the owner's {name} claim: {answer}"
            );
            assert_eq!(
                answer["id"].as_str().unwrap_or_default(),
                id.to_hex(),
                "hydrate serves the owner the {name} claim: {answer}"
            );
        }
        Ok(())
    })
}

#[test]
fn outside_recall_leaves_stamped_claims_out() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let body = json!({"query": SHARED_WORD, "limit": 10});
        let (status, pack) = host.post_as_outside_person(RECALL, body.clone()).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "recall answers 200 for the outside reader: {pack}"
        );
        let names = recall_names(&pack);
        let text = recall_text(&pack);
        assert!(
            names.contains(&host.short_name_of(&host.unstamped)?),
            "recall serves the outside reader the unstamped claim: {pack}"
        );
        assert!(
            names.contains(&host.short_name_of(&host.public)?),
            "recall serves the outside reader the public claim: {pack}"
        );
        assert!(
            !names.contains(&host.short_name_of(&host.private_stamped)?),
            "recall withholds the private stamped claim from the outside reader: {pack}"
        );
        assert!(
            !names.contains(&host.short_name_of(&host.sensitive_stamped)?),
            "recall withholds the sensitive stamped claim from the outside reader: {pack}"
        );
        assert!(
            text.contains(UNSTAMPED_WORD),
            "recall quotes the outside reader the unstamped claim's word: {pack}"
        );
        assert!(
            text.contains(PUBLIC_WORD),
            "recall quotes the outside reader the public claim's word: {pack}"
        );
        assert!(
            !text.contains(PRIVATE_WORD),
            "recall quotes the outside reader none of the private stamped claim's word: {pack}"
        );
        assert!(
            !text.contains(SENSITIVE_WORD),
            "recall quotes the outside reader none of the sensitive stamped claim's word: {pack}"
        );
        let (status, pack) = host.post_as_owner(RECALL, body).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "recall answers 200 for the owner: {pack}"
        );
        let names = recall_names(&pack);
        let text = recall_text(&pack);
        assert!(
            names.contains(&host.short_name_of(&host.unstamped)?),
            "recall serves the owner the unstamped claim: {pack}"
        );
        assert!(
            names.contains(&host.short_name_of(&host.public)?),
            "recall serves the owner the public claim: {pack}"
        );
        assert!(
            names.contains(&host.short_name_of(&host.private_stamped)?),
            "recall serves the owner the private stamped claim: {pack}"
        );
        assert!(
            names.contains(&host.short_name_of(&host.sensitive_stamped)?),
            "recall serves the owner the sensitive stamped claim: {pack}"
        );
        assert!(
            text.contains(UNSTAMPED_WORD)
                && text.contains(PUBLIC_WORD)
                && text.contains(PRIVATE_WORD)
                && text.contains(SENSITIVE_WORD),
            "recall quotes the owner every claim's word: {pack}"
        );
        Ok(())
    })
}

#[test]
fn outside_memory_reason_leaves_stamped_claims_out() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let body = json!({"query": SHARED_WORD, "depth": "medium", "limit": 10});
        let (status, answer) = host.post_as_outside(MEMORY_REASON, body.clone()).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "memory reason answers 200 for the outside reader: {answer}"
        );
        let names = reason_names(&answer);
        let text = answer["answer"].as_str().unwrap_or_default().to_owned();
        assert!(
            names.contains(&host.short_name_of(&host.unstamped)?),
            "memory reason cites the outside reader the unstamped claim: {answer}"
        );
        assert!(
            names.contains(&host.short_name_of(&host.public)?),
            "memory reason cites the outside reader the public claim: {answer}"
        );
        assert!(
            !names.contains(&host.short_name_of(&host.private_stamped)?),
            "memory reason cites the outside reader none of the private stamped claim: {answer}"
        );
        assert!(
            !names.contains(&host.short_name_of(&host.sensitive_stamped)?),
            "memory reason cites the outside reader none of the sensitive stamped claim: {answer}"
        );
        assert!(
            text.contains(UNSTAMPED_WORD),
            "memory reason answers the outside reader with the unstamped claim's word: {answer}"
        );
        assert!(
            text.contains(PUBLIC_WORD),
            "memory reason answers the outside reader with the public claim's word: {answer}"
        );
        assert!(
            !text.contains(PRIVATE_WORD),
            "memory reason answers the outside reader with none of the private stamped claim's word: {answer}"
        );
        assert!(
            !text.contains(SENSITIVE_WORD),
            "memory reason answers the outside reader with none of the sensitive stamped claim's word: {answer}"
        );
        let (status, answer) = host.post_as_owner(MEMORY_REASON, body).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "memory reason answers 200 for the owner: {answer}"
        );
        let names = reason_names(&answer);
        let text = answer["answer"].as_str().unwrap_or_default().to_owned();
        assert!(
            names.contains(&host.short_name_of(&host.unstamped)?),
            "memory reason cites the owner the unstamped claim: {answer}"
        );
        assert!(
            names.contains(&host.short_name_of(&host.public)?),
            "memory reason cites the owner the public claim: {answer}"
        );
        assert!(
            names.contains(&host.short_name_of(&host.private_stamped)?),
            "memory reason cites the owner the private stamped claim: {answer}"
        );
        assert!(
            names.contains(&host.short_name_of(&host.sensitive_stamped)?),
            "memory reason cites the owner the sensitive stamped claim: {answer}"
        );
        assert!(
            text.contains(UNSTAMPED_WORD)
                && text.contains(PUBLIC_WORD)
                && text.contains(PRIVATE_WORD)
                && text.contains(SENSITIVE_WORD),
            "memory reason answers the owner with every claim's word: {answer}"
        );
        Ok(())
    })
}

#[test]
fn own_agent_search_reads_stamped_claims_until_its_slip_moves_keys() -> TestResult {
    on_engine_stack(|| async {
        let host = Host::new()?;
        let path = format!("{TEXT_SEARCH}?query={SHARED_WORD}&limit=10");
        // The vault's own agent reading on its own: green on base and head.
        let (status, answer) = host.get_as_agent(&path).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "text search answers 200 for the vault's own agent: {answer}"
        );
        let ids = search_ids(&answer);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "text search serves the vault's own agent the unstamped claim: {answer}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "text search serves the vault's own agent the public claim: {answer}"
        );
        assert!(
            ids.contains(&host.private_stamped.to_hex()),
            "text search serves the vault's own agent the private stamped claim: {answer}"
        );
        assert!(
            ids.contains(&host.sensitive_stamped.to_hex()),
            "text search serves the vault's own agent the sensitive stamped claim: {answer}"
        );
        // The same slip in another key's hand: red on base, green on head.
        let (status, answer) = host.get_as_transferred(&path).await?;
        assert_eq!(
            status,
            StatusCode::OK,
            "text search answers 200 for the transferred agent slip: {answer}"
        );
        let ids = search_ids(&answer);
        assert!(
            ids.contains(&host.unstamped.to_hex()),
            "text search serves the transferred agent slip the unstamped claim: {answer}"
        );
        assert!(
            ids.contains(&host.public.to_hex()),
            "text search serves the transferred agent slip the public claim: {answer}"
        );
        assert!(
            !ids.contains(&host.private_stamped.to_hex()),
            "text search withholds the private stamped claim from the transferred agent slip: {answer}"
        );
        assert!(
            !ids.contains(&host.sensitive_stamped.to_hex()),
            "text search withholds the sensitive stamped claim from the transferred agent slip: {answer}"
        );
        Ok(())
    })
}
