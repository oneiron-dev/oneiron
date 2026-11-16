//! `vault.mail.reply.approve` at the served door (FIX 18868): a mailbox's own
//! person approves a drafted reply from that mailbox, member or owner, on
//! their own credential. The row's proof is `mailbox_person`: the facade's
//! precheck runs the person proof the door acts under, so a member's own
//! approval reaches the handler instead of meeting the owner refusal.
//!
//! Canon `generated/llms-full.txt:348510`: "Mail-pack drafts are approved
//! through ask cards." The Ask a member's mailbox raises names that member,
//! and its approve tap is this verb.
//!
//! Every approval here is refused before it could send: a stale revision, a
//! mailbox not the caller's, or an agent. No test approves a live draft at
//! its current revision, so nothing reaches a provider. Mail lands through a
//! test-local `MailProviderWire` plus `Vault::mail_sync_step`; the mailboxes
//! are IMAP, whose drafts read nothing at the provider.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test mail_reply_approve_mailbox_person_door`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::mail_pack::{
    MailAttachmentRef, MailFull, MailHeaders, MailHistoryPage, MailHistoryRead, MailIdPage,
    MailListQuery, MailMessageRef, MailProviderWire, MailSyncBudget, MailSyncSource,
};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::secret_custody::{SECRET_CUSTODY_SCHEMA_VERSION, decode_secret_custody_body};
use oneiron::store::GateDecisionId;
use oneiron::verbs::{
    AgentDefinitionCreateRequest, AgentGrantMintRequest, create_agent_definition_as,
    mint_agent_grant_as,
};
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tower::ServiceExt;

const APPROVE: &str = "/v1/core/facade/vault.mail.reply.approve";

struct Fixture {
    vault: Arc<Vault>,
    _dir: tempfile::TempDir,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner_person: EntityId,
}

/// One credential holder, a person or an agent: the actor it names, its
/// slip and its token.
struct Holder {
    id: EntityId,
    slip: CapabilitySlip,
    token: String,
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every holder-bound credential here binds; each holder proves it.
fn holder_key() -> SigningKey {
    SigningKey::from_bytes(&[0x5B; 32])
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after the epoch")
        .as_secs()
}

/// A credential this host mints `holder` as `actor_class`, holding `read`
/// and `write`: a person's or an agent's own slip, not owner-grade.
fn mint_credential(fixture: &Fixture, holder: EntityId, actor_class: &str) -> CapabilitySlip {
    let mut claims = fixture.owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(actor_class.to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("a credential")
}

/// A live PERSON with their own human credential.
fn seed_person(fixture: &Fixture) -> Holder {
    let id = EntityId::now();
    fixture
        .vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let slip = mint_credential(fixture, id, "human");
    let token = slip.to_token().expect("person slip token");
    Holder { id, slip, token }
}

/// An enabled agent the owner creates and gives one Grant naming `read` and
/// the approve verb, with its own agent credential.
fn seed_agent(fixture: &Fixture) -> Holder {
    let id = EntityId::now();
    let proof = fixture
        .vault
        .authenticate_owner(
            fixture.owner_person,
            &fixture.owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("an owner proof");
    create_agent_definition_as(
        &fixture.vault,
        &proof,
        AgentDefinitionCreateRequest {
            agent_def_ref: id,
            definition: serde_json::from_value(json!({
                "agent_id": "mail-approver",
                "desc": "Mail approve door test agent",
                "version": "1.0.0",
                "ceiling": "auto",
                "enabled": true,
            }))
            .expect("typed agent definition"),
        },
    )
    .expect("owner creates an enabled agent definition");
    let mut authority_scope = Scope::top();
    authority_scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "read".to_owned(),
        "vault.mail.reply.approve".to_owned(),
    ]));
    let minted = mint_agent_grant_as(
        &fixture.vault,
        &proof,
        ActSurface::ThisInstall,
        AgentGrantMintRequest {
            agent: id,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "the agent's Grant confers");
    let slip = mint_credential(fixture, id, "agent");
    let token = slip.to_token().expect("agent slip token");
    Holder { id, slip, token }
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("mail-reply-approve-door".into()),
                ..Default::default()
            },
        )
        .expect("create server"),
    );
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let owner_slip = vault
        .ensure_host_root_slip(&issuer)
        .expect("owner root slip");
    let owner_token = owner_slip.to_token().expect("owner slip token");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner_person = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let app = build_app(server);
    Fixture {
        vault,
        _dir: dir,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner_person,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn owner_binding(fixture: &Fixture) -> String {
    let timestamp = fixture.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature: String = hex(&fixture
        .issuer
        .binding_proof(&fixture.owner_slip, challenge.as_bytes())
        .expect("owner holder proof"));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

async fn post(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("x-oneiron-invocation", EntityId::now().to_hex())
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .expect("facade request");
    let response = fixture
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("facade response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("facade response body");
    let answer: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, answer)
}

async fn post_as_owner(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.owner_token.clone();
    post(fixture, path, &token, owner_binding(fixture), body).await
}

async fn post_as(fixture: &Fixture, who: &Holder, path: &str, body: Value) -> (StatusCode, Value) {
    let binding = holder_proof(&who.slip, &holder_key(), fixture.vault.now_recorded_at())
        .expect("holder proof")
        .to_string();
    post(fixture, path, &who.token, binding, body).await
}

/// Registers an IMAP credential under `custody_ref`, stored for `person`
/// (`actor:<PERSON>` in its binding scopes), as `mail_active_sources.rs`
/// registers one through the owner's custody door.
fn register_mail_credential(fixture: &Fixture, custody_ref: &str, person: EntityId) {
    use rmpv::Value;
    let band = |min: u64, max: u64| {
        Value::Map(vec![
            (Value::from("min"), Value::from(min)),
            (Value::from("max"), Value::from(max)),
        ])
    };
    let floor = Value::Map(vec![
        (Value::from("portable"), band(0, 2)),
        (Value::from("device_bound"), band(0, 2)),
        (Value::from("cross_vault"), band(0, 0)),
        (Value::from("rotation_max_age_secs"), Value::Nil),
        (Value::from("env_bindings"), Value::Map(vec![])),
    ]);
    let binding = Value::Map(vec![
        (Value::from("effector"), Value::from("connector:imap")),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (
            Value::from("scopes"),
            Value::Array(vec![Value::from(format!("actor:{}", person.to_hex()))]),
        ),
    ]);
    let body = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (Value::from("name"), Value::from(custody_ref)),
        (Value::from("class"), Value::from("custody-portable")),
        (Value::from("device_only"), Value::from(false)),
        (
            Value::from("value_bytes"),
            Value::Binary(b"test-mail-token".to_vec()),
        ),
        (Value::from("status"), Value::from("active")),
        (Value::from("registered_at"), Value::from(1_u64)),
        (Value::from("rotated_at"), Value::Nil),
        (Value::from("rotation_generation"), Value::from(0_u64)),
        (Value::from("bindings"), Value::Array(vec![binding])),
        (Value::from("manifest_ref"), Value::from("")),
        (Value::from("declared_paths"), Value::Array(vec![])),
        (Value::from("policy_floor_snapshot"), floor),
        (Value::from("model_reveal_allowed"), Value::from(true)),
    ]);
    let mut bytes = Vec::new();
    rmpv::encode::write_value(&mut bytes, &body).expect("custody body encodes");
    fixture
        .vault
        .register_secret(decode_secret_custody_body(&bytes).expect("custody body decodes"))
        .expect("the credential registers");
}

/// A provider wire that serves only the seeded messages, never the network.
struct SeedWire {
    seeds: Vec<MailHeaders>,
}

impl SeedWire {
    fn seed(&self, provider_id: &str) -> Option<&MailHeaders> {
        self.seeds
            .iter()
            .find(|headers| headers.provider_id == provider_id)
    }
}

impl MailProviderWire for SeedWire {
    fn current_anchor(&self, _source: &MailSyncSource) -> oneiron::Result<String> {
        Ok("seed-anchor".to_owned())
    }

    fn list_page(
        &self,
        _source: &MailSyncSource,
        _query: &MailListQuery,
        _page: Option<&str>,
    ) -> oneiron::Result<MailIdPage> {
        Ok(MailIdPage {
            messages: self
                .seeds
                .iter()
                .map(|headers| MailMessageRef {
                    provider_id: headers.provider_id.clone(),
                    thread_id: headers.thread_id.clone(),
                })
                .collect(),
            next_page: None,
        })
    }

    fn headers(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailHeaders>> {
        Ok(self.seed(provider_id).cloned())
    }

    fn full(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailFull>> {
        Ok(self.seed(provider_id).map(|headers| MailFull {
            headers: headers.clone(),
            body_text: Some("Can we move the review to Thursday?".to_owned()),
            attachments: Vec::new(),
            content_digest: None,
        }))
    }

    fn history(
        &self,
        _source: &MailSyncSource,
        _anchor: &str,
        _page: Option<&str>,
    ) -> oneiron::Result<MailHistoryRead> {
        Ok(MailHistoryRead::Page(MailHistoryPage {
            changes: Vec::new(),
            next_page: None,
            anchor: "seed-anchor".to_owned(),
        }))
    }

    fn attachment(
        &self,
        _source: &MailSyncSource,
        _provider_id: &str,
        _attachment: &MailAttachmentRef,
    ) -> oneiron::Result<Option<Vec<u8>>> {
        Ok(None)
    }
}

/// `who`'s own IMAP mailbox, connected by them over the facade, with one
/// received message landed in it. Answers the message's thread ref, read
/// back from `who`'s own inbox.
async fn mailbox_with_one_thread(fixture: &Fixture, who: &Holder, name: &str) -> String {
    let address = format!("{name}@imap.example");
    let custody_ref = format!("{name}-imap");
    register_mail_credential(fixture, &custody_ref, who.id);
    let (status, receipt) = post_as(
        fixture,
        who,
        "/v1/core/facade/vault.mail.sources.connect",
        json!({
            "provider": "imap",
            "kind": "personal_mailbox",
            "address": address,
            "provider_account": format!("{name}-imap-acct"),
            "custody_ref": custody_ref,
            "members": [],
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{name} connects their mailbox: {receipt}"
    );
    let source_ref = receipt["source"]["source_ref"]
        .as_str()
        .expect("a connect answers its source ref")
        .to_owned();
    let received_at = unix_now();
    let wire = SeedWire {
        seeds: vec![MailHeaders {
            provider_id: format!("{name}-msg-1"),
            thread_id: Some(format!("{name}-thread-1")),
            rfc_message_id: Some(format!("<{name}-msg-1@example.com>")),
            from: Some("owen@example.com".to_owned()),
            to: vec![address.clone()],
            subject: Some("Review on Thursday".to_owned()),
            date: Some(received_at),
            received_at,
            labels: vec!["INBOX".to_owned()],
            ..MailHeaders::default()
        }],
    };
    let owner = fixture
        .vault
        .authenticate_owner(
            fixture.owner_person,
            &fixture.owner_person.to_hex(),
            true,
            GateDecisionId::now(),
        )
        .expect("an owner proof for the sync step");
    let source = EntityId::from_hex(&source_ref).expect("a connected source ref");
    fixture
        .vault
        .mail_sync_step(&owner, source, &wire, MailSyncBudget::default())
        .expect("mail lands");
    let (status, page) = post_as(fixture, who, "/v1/core/facade/vault.mail.inbox", json!({})).await;
    assert_eq!(status, StatusCode::OK, "{name} reads their inbox: {page}");
    let item = page["items"]
        .as_array()
        .expect("the inbox answers items")
        .iter()
        .find(|item| item["source_ref"].as_str() == Some(source_ref.as_str()))
        .unwrap_or_else(|| panic!("{name}'s landed message is in their inbox: {page}"));
    item["thread_ref"]
        .as_str()
        .expect("an inbox item names its thread")
        .to_owned()
}

/// `who` drafts a reply on `thread_ref`; answers the draft ref, at revision 1.
async fn draft_reply(fixture: &Fixture, who: &Holder, thread_ref: &str) -> String {
    let (status, draft) = post_as(
        fixture,
        who,
        "/v1/core/facade/vault.mail.reply.draft",
        json!({
            "thread_ref": thread_ref,
            "body": "Thursday works for me.",
            "request_key": "reply-1",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the reply drafts: {draft}");
    assert_eq!(
        draft["revision"].as_u64(),
        Some(1),
        "a first draft is revision 1: {draft}"
    );
    assert_eq!(
        draft["state"].as_str(),
        Some("proposed"),
        "a draft waits for its approval: {draft}"
    );
    draft["draft_ref"]
        .as_str()
        .expect("a draft names its ref")
        .to_owned()
}

/// The pack installed, and a member's and a colleague's own mailboxes, each
/// with one drafted reply of its own person at revision 1.
async fn two_mailboxes_with_drafts() -> (Fixture, Holder, String, Holder, String) {
    let fixture = setup().await;
    let (status, answer) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.mail.pack.install",
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "owner installs the mail pack: {answer}"
    );
    let member = seed_person(&fixture);
    let colleague = seed_person(&fixture);
    let member_thread = mailbox_with_one_thread(&fixture, &member, "member").await;
    let colleague_thread = mailbox_with_one_thread(&fixture, &colleague, "colleague").await;
    let member_draft = draft_reply(&fixture, &member, &member_thread).await;
    let colleague_draft = draft_reply(&fixture, &colleague, &colleague_thread).await;
    (fixture, member, member_draft, colleague, colleague_draft)
}

fn assert_refusal(
    status: StatusCode,
    answer: &Value,
    expected: StatusCode,
    code: &str,
    message: &str,
) {
    assert_eq!(status, expected, "the refusal keeps its status: {answer}");
    assert_eq!(
        answer["error"]["code"].as_str(),
        Some(code),
        "the refusal names its code: {answer}"
    );
    assert_eq!(
        answer["error"]["message"].as_str(),
        Some(message),
        "the refusal names its reason: {answer}"
    );
}

/// A member's approval of their own mailbox's draft reaches the handler on
/// their own credential: a stale revision answers the handler's 409, not
/// the owner refusal (FIX 18868). The current revision is never approved,
/// so nothing sends.
#[test]
fn member_approval_of_own_mailbox_draft_reaches_the_handler() {
    run_on_engine_stack("mail-approve-member-own", || async {
        let (fixture, member, member_draft, _colleague, _colleague_draft) =
            two_mailboxes_with_drafts().await;
        let (status, answer) = post_as(
            &fixture,
            &member,
            APPROVE,
            json!({"draft_ref": member_draft, "revision": 2}),
        )
        .await;
        assert_refusal(
            status,
            &answer,
            StatusCode::CONFLICT,
            "INVALID_STATE",
            "the draft changed since it was reviewed; review its current revision",
        );
    });
}

/// The person proof lends a member no other mailbox: their approval of a
/// colleague's draft answers the handler's 400 for a mailbox not theirs.
/// The revision is stale too, so no check order could let it send.
#[test]
fn member_approval_stays_on_their_own_mailbox() {
    run_on_engine_stack("mail-approve-member-other", || async {
        let (fixture, member, _member_draft, _colleague, colleague_draft) =
            two_mailboxes_with_drafts().await;
        let (status, answer) = post_as(
            &fixture,
            &member,
            APPROVE,
            json!({"draft_ref": colleague_draft, "revision": 2}),
        )
        .await;
        assert_refusal(
            status,
            &answer,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "only the mailbox's own person approves its replies",
        );
    });
}

/// An agent, even one whose Grant names the verb, approves no reply: the
/// person proof refuses its credential before the door runs.
#[test]
fn agent_approval_is_refused_at_the_person_proof() {
    run_on_engine_stack("mail-approve-agent", || async {
        let (fixture, _member, member_draft, _colleague, _colleague_draft) =
            two_mailboxes_with_drafts().await;
        let agent = seed_agent(&fixture);
        let (status, answer) = post_as(
            &fixture,
            &agent,
            APPROVE,
            json!({"draft_ref": member_draft, "revision": 2}),
        )
        .await;
        assert_refusal(
            status,
            &answer,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "vault.mail.reply.approve is a live person's own act",
        );
    });
}
