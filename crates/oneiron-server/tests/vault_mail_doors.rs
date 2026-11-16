//! The mail doors (`vault.mail.*`, ARCH-0063 #mail-pack), entered as the SDK enters
//! them: HTTP `POST /v1/core/facade/<verb>` through the in-process router
//! (`oneshot`, no TCP ports, no sleeps, no provider network).
//!
//! The promises (canon `generated/llms-full.txt:348510`):
//! "Personal mailboxes are private to their owner for ordinary access"
//! (inbox, threads.read, sources.list, threads.share/unshare);
//! "Org compliance search is an admin setting, off by default, and every use is logged."
//! (compliance.setting/set/search/log);
//! "Mail-pack drafts are approved through ask cards."
//! (reply.draft/drafts/discard/approve, and each new revision's Ask to the mailbox's
//! person, read back through `self.inbox.list`).
//! Unproven here: "A member's mailbox stays out by default, and the export notice names
//! it." (`generated/llms-full.txt:348515`, EXPORT-MAILBOXES): it belongs to `vault.export`,
//! whose FIX 15416 work is built on an unopened branch, not on main, so no mail verb
//! proves it.
//! A member approving their own mailbox's draft is refused at the served owner precheck
//! today (FIX 18868 regression; ASK MAIL-REPLY-APPROVE-MEMBER-REFUSED): no test pins a
//! member's approve either way, and an agent's approve asserts status and code only.
//!
//! Each test owns a fresh vault on a `MemoryKeystore`. The pack installs over the facade
//! as the owner; credentials register in-process through `Vault::register_secret` (the
//! `mail_active_sources.rs` recipe); sources connect over `vault.mail.sources.connect`;
//! mail lands through a test-local `MailProviderWire` plus `Vault::mail_sync_step` (the
//! in-crate landing recipe, no network). Every POST carries a fresh
//! `x-oneiron-invocation`. Reply tests use IMAP mailboxes only: a Google draft would read
//! the raw message at the provider.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server
//! --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_mail_doors`.
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
use oneiron::{EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tower::ServiceExt;

struct Fixture {
    vault: Arc<Vault>,
    _dir: tempfile::TempDir,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner_person: EntityId,
    member: EntityId,
    member_slip: CapabilitySlip,
    member_token: String,
    stranger: EntityId,
    stranger_slip: CapabilitySlip,
    stranger_token: String,
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

/// A live PERSON entity, as `graduation_demote_holder_door.rs` places one.
fn seed_person(vault: &Vault) -> EntityId {
    let who = EntityId::now();
    vault
        .put_entity(
            &who,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    who
}

/// A human credential this host mints `who`, holding `read` and `write`:
/// a person's own slip, not owner-grade.
fn mint_person_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential")
}

/// An agent credential this host mints `agent`, holding `read` and `write`.
fn mint_agent_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    agent: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = agent.to_hex();
    claims.actor_class = Some("agent".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("an agent credential")
}

/// A narrowed host-holder slip: holder `host`, verbs `read` + `write`, no
/// principal and no actor class. It passes the scope guards but takes no
/// owner door.
fn mint_narrowed_host_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = "host".to_owned();
    claims.actor_class = None;
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a narrowed host credential")
}

/// A read-only human credential holding `read` only: the scope guard refuses
/// it on every `Write` verb before the body decodes.
fn mint_readonly_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a read-only credential")
}

/// An enabled agent the owner creates and gives one Grant naming `read` and
/// the approve verb, as `delete_authority_served_door.rs` mints its grants.
/// Answers the agent beside its slip and token.
fn agent_with_grant(fixture: &Fixture, agent_id: &str) -> (EntityId, CapabilitySlip, String) {
    let agent = EntityId::now();
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
            agent_def_ref: agent,
            definition: serde_json::from_value(json!({
                "agent_id": agent_id,
                "desc": "Mail door test agent",
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
            agent,
            authority_scope,
            expires_at: None,
            repo_bounds: None,
            verb_classes: BTreeSet::new(),
            wallet_ref: None,
            working_view_bounds: None,
        },
    )
    .expect("owner mints the agent a Grant");
    assert!(minted.grant.confers, "{agent_id}: the Grant confers");
    let slip = mint_agent_credential(&fixture.owner_slip, &fixture.vault, &fixture.issuer, agent);
    let token = slip.to_token().expect("agent slip token");
    (agent, slip, token)
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open_owned(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-mail-doors".into()),
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
    let member = seed_person(&vault);
    let member_slip = mint_person_credential(&owner_slip, &vault, &issuer, member);
    let member_token = member_slip.to_token().expect("member slip token");
    let stranger = seed_person(&vault);
    let stranger_slip = mint_person_credential(&owner_slip, &vault, &issuer, stranger);
    let stranger_token = stranger_slip.to_token().expect("stranger slip token");
    let app = build_app(server);
    Fixture {
        vault,
        _dir: dir,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner_person,
        member,
        member_slip,
        member_token,
        stranger,
        stranger_slip,
        stranger_token,
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

fn holder_binding(fixture: &Fixture, slip: &CapabilitySlip) -> String {
    holder_proof(slip, &holder_key(), fixture.vault.now_recorded_at())
        .expect("holder proof")
        .to_string()
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

async fn post_as_member(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.member_token.clone();
    post(
        fixture,
        path,
        &token,
        holder_binding(fixture, &fixture.member_slip),
        body,
    )
    .await
}

async fn post_as_stranger(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.stranger_token.clone();
    post(
        fixture,
        path,
        &token,
        holder_binding(fixture, &fixture.stranger_slip),
        body,
    )
    .await
}

async fn post_with(
    fixture: &Fixture,
    path: &str,
    token: &str,
    slip: &CapabilitySlip,
    body: Value,
) -> (StatusCode, Value) {
    post(fixture, path, token, holder_binding(fixture, slip), body).await
}

/// The owner installs the Mail & Calendar pack over the facade.
async fn install_pack(fixture: &Fixture) {
    let (status, answer) = post_as_owner(
        fixture,
        "/v1/core/facade/vault.mail.pack.install",
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "owner installs the mail pack: {answer}"
    );
}

/// Registers one source credential under `name`, bound to `effector` with the
/// holder `scopes` (empty for the owner's own), in-process through
/// `Vault::register_secret`, as `crates/oneiron/tests/mail_active_sources.rs`
/// registers one.
fn register_custody(fixture: &Fixture, name: &str, effector: &str, scopes: Vec<&str>) {
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
        (Value::from("effector"), Value::from(effector)),
        (Value::from("tier_ceiling"), Value::from(0_u64)),
        (
            Value::from("scopes"),
            Value::Array(scopes.into_iter().map(Value::from).collect()),
        ),
    ]);
    let body = Value::Map(vec![
        (
            Value::from("schema_version"),
            Value::from(u64::from(SECRET_CUSTODY_SCHEMA_VERSION)),
        ),
        (Value::from("name"), Value::from(name)),
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
        .unwrap_or_else(|err| panic!("the {name} credential registers: {err:?}"));
}

/// Connects one mailbox over the facade as `token`'s holder and answers its
/// source ref.
#[allow(clippy::too_many_arguments)]
async fn connect_source(
    fixture: &Fixture,
    token: &str,
    binding: String,
    provider: &str,
    kind: &str,
    address: &str,
    account: &str,
    custody: &str,
    members: Vec<String>,
) -> String {
    let (status, receipt) = post(
        fixture,
        "/v1/core/facade/vault.mail.sources.connect",
        token,
        binding,
        json!({
            "provider": provider,
            "kind": kind,
            "address": address,
            "provider_account": account,
            "custody_ref": custody,
            "members": members,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the {address} source connects: {receipt}"
    );
    assert_eq!(
        receipt["resumed"].as_bool(),
        Some(false),
        "the connect is fresh, not resumed: {receipt}"
    );
    receipt["source"]["source_ref"]
        .as_str()
        .expect("a connect answers its source ref")
        .to_owned()
}

/// One message a test lands: its headers and its plain-text body.
struct SeedMessage {
    headers: MailHeaders,
    body: String,
}

/// A provider wire that serves only the seeded messages, never the network.
struct SeedWire {
    seeds: Vec<SeedMessage>,
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
                .map(|seed| MailMessageRef {
                    provider_id: seed.headers.provider_id.clone(),
                    thread_id: seed.headers.thread_id.clone(),
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
        Ok(self
            .seeds
            .iter()
            .find(|seed| seed.headers.provider_id == provider_id)
            .map(|seed| seed.headers.clone()))
    }

    fn full(
        &self,
        _source: &MailSyncSource,
        provider_id: &str,
    ) -> oneiron::Result<Option<MailFull>> {
        Ok(self
            .seeds
            .iter()
            .find(|seed| seed.headers.provider_id == provider_id)
            .map(|seed| MailFull {
                headers: seed.headers.clone(),
                body_text: Some(seed.body.clone()),
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

/// A received message's headers: from Owen to the mailbox, in `thread_id`.
fn seed_message(
    provider_id: &str,
    thread_id: &str,
    subject: &str,
    body: &str,
    mailbox: &str,
    received_at: u64,
) -> SeedMessage {
    SeedMessage {
        headers: MailHeaders {
            provider_id: provider_id.to_owned(),
            thread_id: Some(thread_id.to_owned()),
            rfc_message_id: Some(format!("<{provider_id}@example.com>")),
            in_reply_to: None,
            references: Vec::new(),
            from: Some("owen@example.com".to_owned()),
            to: vec![mailbox.to_owned()],
            cc: Vec::new(),
            reply_to: Vec::new(),
            subject: Some(subject.to_owned()),
            date: Some(received_at),
            received_at,
            labels: vec!["INBOX".to_owned()],
            sent_by_mailbox: false,
            trash_or_spam: false,
            draft: false,
        },
        body: body.to_owned(),
    }
}

/// Lands `seeds` into `source_ref` through one sync step under the embedded
/// owner's proof, exactly as the in-crate landing recipe does.
fn land_seeds(fixture: &Fixture, source_ref: &str, seeds: Vec<SeedMessage>) {
    let memory = fixture
        .vault
        .memory(fixture.owner_person, EdgeActorClass::Human);
    let proof = memory
        .embedded_owner("vault.mail.sources.sync")
        .expect("the sync step's owner proof");
    let source = EntityId::from_hex(source_ref).expect("a connected source ref");
    let wire = SeedWire { seeds };
    fixture
        .vault
        .mail_sync_step(&proof, source, &wire, MailSyncBudget::default())
        .expect("mail lands");
}

/// The member's own mailbox: custody stored for the member, connected by the
/// member over the facade. Answers its source ref.
async fn member_mailbox(fixture: &Fixture) -> String {
    let member_hex = fixture.member.to_hex();
    let scope = format!("actor:{member_hex}");
    register_custody(fixture, "member-imap", "connector:imap", vec![&scope]);
    let token = fixture.member_token.clone();
    connect_source(
        fixture,
        &token,
        holder_binding(fixture, &fixture.member_slip),
        "imap",
        "personal_mailbox",
        "member@imap.example",
        "member-imap-acct",
        "member-imap",
        Vec::new(),
    )
    .await
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

/// The rows of a `self.inbox.list` page.
fn inbox_rows(page: &Value) -> &Vec<Value> {
    page["rows"].as_array().expect("inbox.list answers rows")
}

/// The `mail.reply` Ask row for revision `revision` of `draft`, if listed.
fn ask_row<'a>(page: &'a Value, draft: &str, revision: u64) -> Option<&'a Value> {
    let event = format!("{draft}:{revision}");
    inbox_rows(page).iter().find(|row| {
        row["kind"].as_str() == Some("ask")
            && row["source"]["producer"].as_str() == Some("mail.reply")
            && row["source"]["result"].as_str() == Some(draft)
            && row["source"]["event"].as_str() == Some(event.as_str())
    })
}

/// The thread ref of the inbox item with `subject`, picked by subject rather than by
/// index, so a widened inbox cannot misroute the fixture under a seeded fault.
fn thread_ref_by_subject(page: &Value, subject: &str) -> String {
    page["items"]
        .as_array()
        .expect("the inbox answers items")
        .iter()
        .find(|item| item["subject"].as_str() == Some(subject))
        .unwrap_or_else(|| panic!("the {subject} thread lists: {page}"))["thread_ref"]
        .as_str()
        .expect("an inbox item names its thread")
        .to_owned()
}

/// A personal mailbox is private to its owner for ordinary access: the
/// owner's inbox and sources list show it, the member's omit it entirely,
/// and the member's and a stranger's reads of the owner's thread are 404
/// with the same code and reason (request_id differs by design).
///
/// Canon `generated/llms-full.txt:348510` "Personal mailboxes are private to
/// their owner for ordinary access".
#[test]
fn owner_mailbox_is_private_to_its_owner() {
    run_on_engine_stack("mail-private", || async {
        let fixture = setup().await;
        install_pack(&fixture).await;
        register_custody(&fixture, "owner-gmail", "connector:gmail", Vec::new());
        let token = fixture.owner_token.clone();
        let source = connect_source(
            &fixture,
            &token,
            owner_binding(&fixture),
            "google",
            "personal_mailbox",
            "owner@gmail.example",
            "owner-google-acct",
            "owner-gmail",
            Vec::new(),
        )
        .await;
        let received = fixture.vault.now_recorded_at();
        land_seeds(
            &fixture,
            &source,
            vec![seed_message(
                "owner-msg-1",
                "owner-thread-1",
                "Quarterly plan",
                "Can we move the review to Thursday?",
                "owner@gmail.example",
                received,
            )],
        );

        let (status, page) =
            post_as_owner(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(status, StatusCode::OK, "the owner reads the inbox: {page}");
        let items = page["items"].as_array().expect("the inbox answers items");
        assert_eq!(items.len(), 1, "the owner's message lists: {page}");
        assert_eq!(
            items[0]["source_ref"].as_str(),
            Some(source.as_str()),
            "the item names its source: {page}"
        );
        assert_eq!(
            items[0]["shared_with_reader"].as_bool(),
            Some(false),
            "the owner reads it as the source's reader: {page}"
        );
        let thread = items[0]["thread_ref"]
            .as_str()
            .expect("an inbox item names its thread")
            .to_owned();

        let (status, listed) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.sources.list",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the sources list: {listed}"
        );
        let rows = listed.as_array().expect("sources.list answers a list");
        let own = rows
            .iter()
            .find(|row| row["source_ref"].as_str() == Some(source.as_str()))
            .unwrap_or_else(|| panic!("the owner's mailbox lists: {listed}"));
        assert_eq!(
            own["address"].as_str(),
            Some("owner@gmail.example"),
            "the owner reads the mailbox address: {listed}"
        );

        let (status, hidden_inbox) =
            post_as_member(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member's inbox reads: {hidden_inbox}"
        );
        assert_eq!(
            hidden_inbox["items"]
                .as_array()
                .expect("the inbox answers items")
                .len(),
            0,
            "the member's inbox omits the owner's mailbox: {hidden_inbox}"
        );

        let (status, hidden_list) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.sources.list",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member's sources list reads: {hidden_list}"
        );
        assert_eq!(
            hidden_list.as_array().expect("a list").len(),
            0,
            "the member's sources list omits the owner's mailbox: {hidden_list}"
        );
        assert!(
            !hidden_list.to_string().contains("owner@gmail.example"),
            "the member's list names no mailbox name: {hidden_list}"
        );
        assert!(
            !hidden_list.to_string().contains(&source),
            "the member's list names no mailbox ref: {hidden_list}"
        );

        let (member_status, member_read) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.threads.read",
            json!({"thread_ref": thread.clone()}),
        )
        .await;
        assert_refusal(
            member_status,
            &member_read,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail thread by that ref",
        );
        let (stranger_status, stranger_read) = post_as_stranger(
            &fixture,
            "/v1/core/facade/vault.mail.threads.read",
            json!({"thread_ref": thread.clone()}),
        )
        .await;
        assert_refusal(
            stranger_status,
            &stranger_read,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail thread by that ref",
        );
        assert_eq!(
            member_read["error"]["code"].as_str(),
            stranger_read["error"]["code"].as_str(),
            "a stranger's refusal names the same code as the member's"
        );
        assert_eq!(
            member_read["error"]["message"].as_str(),
            stranger_read["error"]["message"].as_str(),
            "a stranger's refusal names the same reason as the member's \
             (request_id differs by design)"
        );
    });
}

/// A share reaches the thread alone: after it the member reads that thread
/// and the inbox lists only its items, marked shared, while the sources list
/// still hides the mailbox; the member leaving removes them again.
///
/// Canon `generated/llms-full.txt:348510` "Personal mailboxes are private to
/// their owner for ordinary access".
#[test]
fn share_reaches_the_thread_alone() {
    run_on_engine_stack("mail-share", || async {
        let fixture = setup().await;
        install_pack(&fixture).await;
        register_custody(&fixture, "owner-gmail", "connector:gmail", Vec::new());
        let token = fixture.owner_token.clone();
        let source = connect_source(
            &fixture,
            &token,
            owner_binding(&fixture),
            "google",
            "personal_mailbox",
            "owner@gmail.example",
            "owner-google-acct",
            "owner-gmail",
            Vec::new(),
        )
        .await;
        let received = fixture.vault.now_recorded_at();
        land_seeds(
            &fixture,
            &source,
            vec![
                seed_message(
                    "owner-msg-1",
                    "owner-thread-1",
                    "Quarterly plan",
                    "Can we move the review to Thursday?",
                    "owner@gmail.example",
                    received,
                ),
                seed_message(
                    "owner-msg-2",
                    "owner-thread-2",
                    "Offsite",
                    "The offsite moves to March.",
                    "owner@gmail.example",
                    received,
                ),
            ],
        );
        let member_hex = fixture.member.to_hex();

        let (status, page) =
            post_as_owner(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(status, StatusCode::OK, "the owner reads the inbox: {page}");
        let items = page["items"].as_array().expect("the inbox answers items");
        assert_eq!(items.len(), 2, "both messages list: {page}");
        let thread = items
            .iter()
            .find(|item| item["subject"].as_str() == Some("Quarterly plan"))
            .unwrap_or_else(|| panic!("the first thread lists: {page}"))["thread_ref"]
            .as_str()
            .expect("an item names its thread")
            .to_owned();

        let (status, receipt) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.threads.share",
            json!({"record_ref": thread.clone(), "person_ref": member_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner shares the thread: {receipt}"
        );
        assert_eq!(
            receipt["shared"].as_bool(),
            Some(true),
            "the share lands: {receipt}"
        );
        assert_eq!(
            receipt["person_ref"].as_str(),
            Some(member_hex.as_str()),
            "the share names its person: {receipt}"
        );

        let (status, view) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.threads.read",
            json!({"thread_ref": thread.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member reads the shared thread: {view}"
        );
        assert_eq!(
            view["messages"].as_array().expect("a thread view").len(),
            1,
            "the thread carries its message: {view}"
        );

        let (status, shared_page) =
            post_as_member(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member's inbox reads: {shared_page}"
        );
        let shared_items = shared_page["items"]
            .as_array()
            .expect("the inbox answers items");
        assert_eq!(
            shared_items.len(),
            1,
            "the inbox lists only the shared thread's items: {shared_page}"
        );
        assert_eq!(
            shared_items[0]["thread_ref"].as_str(),
            Some(thread.as_str()),
            "the item is the shared thread's: {shared_page}"
        );
        assert_eq!(
            shared_items[0]["shared_with_reader"].as_bool(),
            Some(true),
            "the item reads shared with its reader: {shared_page}"
        );

        let (status, hidden_list) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.sources.list",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member's sources list reads: {hidden_list}"
        );
        assert_eq!(
            hidden_list.as_array().expect("a list").len(),
            0,
            "the share widens no mailbox: {hidden_list}"
        );

        let (status, left) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.threads.unshare",
            json!({"record_ref": thread.clone(), "person_ref": member_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member leaves the thread: {left}"
        );
        assert_eq!(
            left["shared"].as_bool(),
            Some(false),
            "the share is withdrawn: {left}"
        );

        let (status, emptied) =
            post_as_member(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member's inbox reads again: {emptied}"
        );
        assert_eq!(
            emptied["items"].as_array().expect("items").len(),
            0,
            "leaving removes the thread's items: {emptied}"
        );
        let (gone_status, gone) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.threads.read",
            json!({"thread_ref": thread.clone()}),
        )
        .await;
        assert_refusal(
            gone_status,
            &gone,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail thread by that ref",
        );
    });
}

/// Org compliance search is an admin setting, off by default: a fresh vault answers
/// disabled to everyone, the owner searches nothing while it is off, a member turns it
/// on nowhere, and the owner turns it on.
///
/// Canon `generated/llms-full.txt:348510` "Org compliance search is an admin setting, off
/// by default, and every use is logged."
#[test]
fn compliance_search_is_off_by_default_and_admin_only() {
    run_on_engine_stack("mail-compliance-off", || async {
        let fixture = setup().await;
        install_pack(&fixture).await;

        let (status, owner_setting) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.setting",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the setting: {owner_setting}"
        );
        assert_eq!(
            owner_setting["enabled"].as_bool(),
            Some(false),
            "a fresh vault answers disabled: {owner_setting}"
        );
        let (status, member_setting) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.setting",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member reads the setting: {member_setting}"
        );
        assert_eq!(
            member_setting["enabled"].as_bool(),
            Some(false),
            "a fresh vault answers disabled to the member too: {member_setting}"
        );
        let (status, stranger_setting) = post_as_stranger(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.setting",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a stranger reads the setting: {stranger_setting}"
        );
        assert_eq!(
            stranger_setting["enabled"].as_bool(),
            Some(false),
            "a fresh vault answers disabled to a stranger too: {stranger_setting}"
        );

        let (off_status, off_search) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.search",
            json!({"query": "plan", "purpose": "audit"}),
        )
        .await;
        assert_refusal(
            off_status,
            &off_search,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "org compliance search is off, or the caller is not the vault's Owner or an Admin",
        );

        let (member_status, member_set) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.set",
            json!({"enabled": true, "purpose": "audit"}),
        )
        .await;
        assert_refusal(
            member_status,
            &member_set,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "org compliance search is set by the vault's Owner or an Admin",
        );

        let (status, enabled) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.set",
            json!({"enabled": true, "purpose": "q4 audit"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner turns the setting on: {enabled}"
        );
        assert_eq!(
            enabled["enabled"].as_bool(),
            Some(true),
            "the setting answers on: {enabled}"
        );
    });
}

/// Every compliance use is logged: enabling writes its Enabled row, a search answers
/// beside the Search row it wrote first (same sequence, purpose, query digest instead
/// of the words, result count), and a member reads no log. It asserts the log half
/// only, not hit content: whether landing BM25-indexes bodies in time for a synchronous
/// search was not provable by reading.
///
/// Canon `generated/llms-full.txt:348510` "Org compliance search is an admin setting, off
/// by default, and every use is logged."
#[test]
fn every_compliance_use_is_logged() {
    run_on_engine_stack("mail-compliance-log", || async {
        let fixture = setup().await;
        install_pack(&fixture).await;
        register_custody(&fixture, "owner-gmail", "connector:gmail", Vec::new());
        let token = fixture.owner_token.clone();
        let owner_source = connect_source(
            &fixture,
            &token,
            owner_binding(&fixture),
            "google",
            "personal_mailbox",
            "owner@gmail.example",
            "owner-google-acct",
            "owner-gmail",
            Vec::new(),
        )
        .await;
        let member_source = member_mailbox(&fixture).await;
        let received = fixture.vault.now_recorded_at();
        land_seeds(
            &fixture,
            &owner_source,
            vec![seed_message(
                "owner-msg-1",
                "owner-thread-1",
                "Quarterly plan",
                "Can we move the review to Thursday?",
                "owner@gmail.example",
                received,
            )],
        );
        land_seeds(
            &fixture,
            &member_source,
            vec![seed_message(
                "member-msg-1",
                "member-thread-1",
                "Thursday rota",
                "The Thursday rota is posted.",
                "member@imap.example",
                received,
            )],
        );

        let (status, enabled) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.set",
            json!({"enabled": true, "purpose": "q4 audit rotation"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner turns the setting on: {enabled}"
        );

        let (status, log) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.log",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner reads the log: {log}");
        let entries = log.as_array().expect("the log answers entries");
        assert_eq!(entries.len(), 1, "enabling writes one row: {log}");
        assert_eq!(
            entries[0]["kind"].as_str(),
            Some("enabled"),
            "the row records the enabling: {log}"
        );
        assert_eq!(
            entries[0]["sequence"].as_u64(),
            Some(1),
            "the first row is sequenced first: {log}"
        );
        assert_eq!(
            entries[0]["purpose"].as_str(),
            Some("q4 audit rotation"),
            "the row keeps its purpose: {log}"
        );
        assert_eq!(
            entries[0]["by_ref"].as_str(),
            Some(fixture.owner_person.to_hex().as_str()),
            "the row names its setter: {log}"
        );

        let (status, searched) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.search",
            json!({"query": "Thursday", "purpose": "find the thursday thread"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner searches while on: {searched}"
        );
        let sequence = searched["log_sequence"]
            .as_u64()
            .expect("a search answers its log sequence");
        let hits = searched["hits"].as_array().expect("a search answers hits");
        for hit in hits {
            assert_eq!(
                hit["message_ref"].as_str().map(str::len),
                Some(32),
                "a hit names its message: {searched}"
            );
            assert_eq!(
                hit["source_ref"].as_str().map(str::len),
                Some(32),
                "a hit names its source: {searched}"
            );
        }

        let (status, grown) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.log",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the log again: {grown}"
        );
        let grown_entries = grown.as_array().expect("the log answers entries");
        assert_eq!(
            grown_entries.len(),
            2,
            "the search grows the log by one row: {grown}"
        );
        let logged = &grown_entries[1];
        assert_eq!(
            logged["sequence"].as_u64(),
            Some(sequence),
            "the new row carries the reply's sequence: {grown}"
        );
        assert_eq!(
            logged["kind"].as_str(),
            Some("search"),
            "the new row records the search: {grown}"
        );
        assert_eq!(
            logged["purpose"].as_str(),
            Some("find the thursday thread"),
            "the new row keeps its purpose: {grown}"
        );
        let digest = logged["query_digest"]
            .as_str()
            .expect("a search row keeps its query digest");
        assert_eq!(digest.len(), 64, "the digest is a BLAKE3 hex: {grown}");
        assert!(
            digest.chars().all(char::is_ascii_hexdigit),
            "the digest is hex, not the words: {grown}"
        );
        assert_ne!(digest, "Thursday", "the log keeps no search words: {grown}");
        assert_eq!(
            logged["result_count"].as_u64(),
            Some(hits.len() as u64),
            "the row counts what the search found: {grown}"
        );

        let (member_status, member_log) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.log",
            json!({}),
        )
        .await;
        assert_refusal(
            member_status,
            &member_log,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no compliance log for this reader",
        );
    });
}

/// A reply draft holds until approved: it answers Proposed with a frozen plan and sends
/// nothing, the same words keep the revision, changed words bump it, and the drafts list
/// shows it to thread readers only.
///
/// Canon `generated/llms-full.txt:348510` "Mail-pack drafts are approved through ask
/// cards."
#[test]
fn reply_draft_holds_until_approved() {
    run_on_engine_stack("mail-draft-holds", || async {
        let fixture = setup().await;
        install_pack(&fixture).await;
        register_custody(&fixture, "owner-imap", "connector:imap", Vec::new());
        let token = fixture.owner_token.clone();
        let source = connect_source(
            &fixture,
            &token,
            owner_binding(&fixture),
            "imap",
            "personal_mailbox",
            "owner@imap.example",
            "owner-imap-acct",
            "owner-imap",
            Vec::new(),
        )
        .await;
        let received = fixture.vault.now_recorded_at();
        land_seeds(
            &fixture,
            &source,
            vec![seed_message(
                "owner-msg-1",
                "owner-thread-1",
                "Quarterly plan",
                "Can we move the review to Thursday?",
                "owner@imap.example",
                received,
            )],
        );

        let (status, page) =
            post_as_owner(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(status, StatusCode::OK, "the owner reads the inbox: {page}");
        let thread = thread_ref_by_subject(&page, "Quarterly plan");

        let (status, first) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": thread.clone(),
                "body": "Thursday works for me.",
                "request_key": "t5-first",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner drafts a reply: {first}");
        assert_eq!(
            first["state"].as_str(),
            Some("proposed"),
            "the draft waits Proposed: {first}"
        );
        assert_eq!(
            first["revision"].as_u64(),
            Some(1),
            "the first words are the first revision: {first}"
        );
        let draft = first["draft_ref"]
            .as_str()
            .expect("a draft answers its ref")
            .to_owned();
        let plan = first["plan_ref"]
            .as_str()
            .expect("a draft answers its frozen plan")
            .to_owned();
        assert!(
            first.get("outcome").is_none_or(Value::is_null),
            "nothing sent, so no outcome: {first}"
        );

        let (status, same) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": thread.clone(),
                "body": "Thursday works for me.",
                "request_key": "t5-first",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the same words draft again: {same}");
        assert_eq!(
            same["revision"].as_u64(),
            Some(1),
            "the same words keep the revision: {same}"
        );
        assert_eq!(
            same["plan_ref"].as_str(),
            Some(plan.as_str()),
            "the same words keep the frozen plan: {same}"
        );

        let (status, bumped) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": thread.clone(),
                "body": "Thursday works for me, in the afternoon.",
                "request_key": "t5-first",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "changed words draft again: {bumped}"
        );
        assert_eq!(
            bumped["revision"].as_u64(),
            Some(2),
            "changed words bump the revision: {bumped}"
        );
        assert_eq!(
            bumped["state"].as_str(),
            Some("proposed"),
            "the new revision waits Proposed too: {bumped}"
        );

        let (status, drafts) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.drafts",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner lists the drafts: {drafts}"
        );
        assert!(
            drafts["drafts"]
                .as_array()
                .expect("drafts answer a list")
                .iter()
                .any(|row| row["draft_ref"].as_str() == Some(draft.as_str())),
            "the thread's reader lists the draft: {drafts}"
        );
        let (status, hidden) = post_as_stranger(
            &fixture,
            "/v1/core/facade/vault.mail.reply.drafts",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a stranger lists the drafts: {hidden}"
        );
        assert_eq!(
            hidden["drafts"].as_array().expect("a list").len(),
            0,
            "a stranger lists no draft: {hidden}"
        );
    });
}

/// Each new revision raises an Ask to the mailbox's person, with approve and discard
/// taps; discard clears it; the owner drafting on their own mailbox raises none.
///
/// Canon `generated/llms-full.txt:348510` "Mail-pack drafts are approved through ask
/// cards."
#[test]
fn reply_revision_raises_ask_to_mailbox_person() {
    run_on_engine_stack("mail-draft-ask", || async {
        let fixture = setup().await;
        install_pack(&fixture).await;
        register_custody(&fixture, "owner-imap", "connector:imap", Vec::new());
        let token = fixture.owner_token.clone();
        let source = connect_source(
            &fixture,
            &token,
            owner_binding(&fixture),
            "imap",
            "personal_mailbox",
            "owner@imap.example",
            "owner-imap-acct",
            "owner-imap",
            Vec::new(),
        )
        .await;
        let received = fixture.vault.now_recorded_at();
        land_seeds(
            &fixture,
            &source,
            vec![seed_message(
                "owner-msg-1",
                "owner-thread-1",
                "Quarterly plan",
                "Can we move the review to Thursday?",
                "owner@imap.example",
                received,
            )],
        );
        let member_hex = fixture.member.to_hex();

        let (status, page) =
            post_as_owner(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(status, StatusCode::OK, "the owner reads the inbox: {page}");
        let thread = thread_ref_by_subject(&page, "Quarterly plan");
        let (status, _) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.threads.share",
            json!({"record_ref": thread.clone(), "person_ref": member_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner shares the thread");

        let (status, first) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": thread.clone(),
                "body": "Friday works for me.",
                "request_key": "t6-member",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member drafts on the shared thread: {first}"
        );
        assert_eq!(
            first["revision"].as_u64(),
            Some(1),
            "the first words are the first revision: {first}"
        );
        let draft = first["draft_ref"]
            .as_str()
            .expect("a draft answers its ref")
            .to_owned();

        let (status, asked) =
            post_as_owner(&fixture, "/v1/core/facade/self.inbox.list", json!({})).await;
        assert_eq!(status, StatusCode::OK, "the owner reads the inbox: {asked}");
        let card = ask_row(&asked, &draft, 1)
            .unwrap_or_else(|| panic!("the revision raises its Ask: {asked}"));
        assert_eq!(
            card["acked"].as_bool(),
            Some(false),
            "the Ask waits unacked: {asked}"
        );
        let taps = card["actions"]
            .as_array()
            .expect("the Ask carries its taps");
        assert_eq!(taps.len(), 2, "the Ask carries both taps: {asked}");
        assert_eq!(
            taps[0]["verb"].as_str(),
            Some("vault.mail.reply.approve"),
            "the first tap approves: {asked}"
        );
        assert_eq!(
            taps[0]["args"]["draft_ref"].as_str(),
            Some(draft.as_str()),
            "the approve tap names the draft: {asked}"
        );
        assert_eq!(
            taps[0]["args"]["revision"].as_u64(),
            Some(1),
            "the approve tap names the revision: {asked}"
        );
        assert_eq!(
            taps[1]["verb"].as_str(),
            Some("vault.mail.reply.discard"),
            "the second tap discards: {asked}"
        );
        assert_eq!(
            taps[1]["args"]["draft_ref"].as_str(),
            Some(draft.as_str()),
            "the discard tap names the draft: {asked}"
        );

        let (status, bumped) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": thread.clone(),
                "body": "Friday works for me, in the morning.",
                "request_key": "t6-member",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "changed words draft again: {bumped}"
        );
        assert_eq!(
            bumped["revision"].as_u64(),
            Some(2),
            "changed words bump the revision: {bumped}"
        );

        let (status, reasked) =
            post_as_owner(&fixture, "/v1/core/facade/self.inbox.list", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the inbox again: {reasked}"
        );
        let old = ask_row(&reasked, &draft, 1)
            .unwrap_or_else(|| panic!("the replaced Ask still lists: {reasked}"));
        assert_eq!(
            old["acked"].as_bool(),
            Some(true),
            "the replaced revision is no longer asked: {reasked}"
        );
        let current = ask_row(&reasked, &draft, 2)
            .unwrap_or_else(|| panic!("the new revision raises its Ask: {reasked}"));
        assert_eq!(
            current["acked"].as_bool(),
            Some(false),
            "the new Ask waits unacked: {reasked}"
        );

        let (status, cleared) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.reply.discard",
            json!({"draft_ref": draft.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the drafter discards the draft: {cleared}"
        );
        assert_eq!(
            cleared["state"].as_str(),
            Some("discarded"),
            "the discard lands: {cleared}"
        );

        let (status, settled) =
            post_as_owner(&fixture, "/v1/core/facade/self.inbox.list", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the inbox once more: {settled}"
        );
        let done = ask_row(&settled, &draft, 2)
            .unwrap_or_else(|| panic!("the cleared Ask still lists: {settled}"));
        assert_eq!(
            done["acked"].as_bool(),
            Some(true),
            "discard clears the Ask: {settled}"
        );
        assert!(
            done["actions"].as_array().is_none_or(Vec::is_empty),
            "the cleared Ask offers no taps: {settled}"
        );

        let (status, own) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": thread.clone(),
                "body": "Thursday works for me.",
                "request_key": "t6-owner",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner drafts on their own mailbox: {own}"
        );
        let own_draft = own["draft_ref"]
            .as_str()
            .expect("a draft answers its ref")
            .to_owned();
        let (status, quiet) =
            post_as_owner(&fixture, "/v1/core/facade/self.inbox.list", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner reads the inbox last: {quiet}"
        );
        assert!(
            inbox_rows(&quiet)
                .iter()
                .all(|row| row["source"]["result"].as_str() != Some(own_draft.as_str())),
            "the owner's own draft raises no Ask: {quiet}"
        );
    });
}

/// Approving refuses the wrong mailbox, a stale revision, and a discarded draft: an
/// agent's approve is refused, the owner approving the member's mailbox meets the
/// handler's own-person gate, and a wrong revision or a discarded draft is refused. No
/// live draft is ever approved with its right revision, so nothing dispatches.
/// A member approving their own mailbox's draft is refused at the served owner precheck
/// today (FIX 18868 regression; ASK MAIL-REPLY-APPROVE-MEMBER-REFUSED); the fix PR
/// proves that half.
///
/// Canon `generated/llms-full.txt:348510` "Mail-pack drafts are approved through ask
/// cards."
#[test]
fn reply_approve_refuses_other_mailbox_stale_and_discarded() {
    run_on_engine_stack("mail-approve", || async {
        let fixture = setup().await;
        install_pack(&fixture).await;
        register_custody(&fixture, "owner-imap", "connector:imap", Vec::new());
        let token = fixture.owner_token.clone();
        let owner_source = connect_source(
            &fixture,
            &token,
            owner_binding(&fixture),
            "imap",
            "personal_mailbox",
            "owner@imap.example",
            "owner-imap-acct",
            "owner-imap",
            Vec::new(),
        )
        .await;
        let member_source = member_mailbox(&fixture).await;
        let received = fixture.vault.now_recorded_at();
        land_seeds(
            &fixture,
            &owner_source,
            vec![seed_message(
                "owner-msg-1",
                "owner-thread-1",
                "Quarterly plan",
                "Can we move the review to Thursday?",
                "owner@imap.example",
                received,
            )],
        );
        land_seeds(
            &fixture,
            &member_source,
            vec![seed_message(
                "member-msg-1",
                "member-thread-1",
                "Thursday rota",
                "The Thursday rota is posted.",
                "member@imap.example",
                received,
            )],
        );

        let (status, page) =
            post_as_owner(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(status, StatusCode::OK, "the owner reads the inbox: {page}");
        let thread = thread_ref_by_subject(&page, "Quarterly plan");
        let (status, member_page) =
            post_as_member(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member reads the inbox: {member_page}"
        );
        let member_thread = thread_ref_by_subject(&member_page, "Thursday rota");

        let (status, member_draft) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": member_thread,
                "body": "Noted, thanks.",
                "request_key": "t7-member",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member drafts on their own mailbox: {member_draft}"
        );
        let member_ref = member_draft["draft_ref"]
            .as_str()
            .expect("a draft answers its ref")
            .to_owned();
        let (status, owner_draft) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": thread,
                "body": "Thursday works for me.",
                "request_key": "t7-owner",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner drafts on their own mailbox: {owner_draft}"
        );
        let owner_ref = owner_draft["draft_ref"]
            .as_str()
            .expect("a draft answers its ref")
            .to_owned();

        let (_agent, agent_slip, agent_token) = agent_with_grant(&fixture, "mail_approve_agent");
        let (agent_status, agent_answer) = post_with(
            &fixture,
            "/v1/core/facade/vault.mail.reply.approve",
            &agent_token,
            &agent_slip,
            json!({"draft_ref": owner_ref.clone(), "revision": 1}),
        )
        .await;
        assert_eq!(
            agent_status,
            StatusCode::FORBIDDEN,
            "the agent's approve is refused: {agent_answer}"
        );
        assert_eq!(
            agent_answer["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {agent_answer}"
        );
        let (other_status, other_answer) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.approve",
            json!({"draft_ref": member_ref, "revision": 1}),
        )
        .await;
        assert_refusal(
            other_status,
            &other_answer,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "only the mailbox's own person approves its replies",
        );
        let (stale_status, stale_answer) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.approve",
            json!({"draft_ref": owner_ref.clone(), "revision": 999}),
        )
        .await;
        assert_refusal(
            stale_status,
            &stale_answer,
            StatusCode::CONFLICT,
            "INVALID_STATE",
            "the draft changed since it was reviewed; review its current revision",
        );

        let (status, discarded) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.discard",
            json!({"draft_ref": owner_ref.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner discards the draft: {discarded}"
        );
        let (dead_status, dead_answer) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.approve",
            json!({"draft_ref": owner_ref.clone(), "revision": 1}),
        )
        .await;
        assert_refusal(
            dead_status,
            &dead_answer,
            StatusCode::CONFLICT,
            "INVALID_STATE",
            "the draft was discarded; it never sends",
        );
    });
}

/// The mail doors' refusal table: every row names its status, code, message and layer,
/// except row 5 (an agent's approve: status and code only, as the served precheck's
/// message changes with the FIX 18868 fix). Row 27 (discarding an approved draft) is
/// dropped: reaching Approved needs a dispatch, which needs provider network. Row 28
/// (a member's approve) is dropped too: it is refused at the served owner precheck
/// today (FIX 18868 regression; ASK MAIL-REPLY-APPROVE-MEMBER-REFUSED); the handler's
/// own-person gate is the added row after 28's place.
///
/// Canon `generated/llms-full.txt:348510` (each row guards one of the three promises).
// The table's 39 rows share one fixture with interleaved stateful setup; splitting
// the test would fork that fixture per row group for no gain.
#[allow(clippy::too_many_lines)]
#[test]
fn mail_doors_refusal_table() {
    run_on_engine_stack("mail-refusals", || async {
        let fixture = setup().await;
        install_pack(&fixture).await;
        register_custody(&fixture, "owner-gmail", "connector:gmail", Vec::new());
        register_custody(&fixture, "owner-imap", "connector:imap", Vec::new());
        register_custody(&fixture, "owner-m365", "connector:microsoft365", Vec::new());
        let member_hex = fixture.member.to_hex();
        let stranger_hex = fixture.stranger.to_hex();
        let member_scope = format!("actor:{member_hex}");
        register_custody(
            &fixture,
            "member-imap",
            "connector:imap",
            vec![&member_scope],
        );
        register_custody(
            &fixture,
            "group-mail",
            "connector:gmail",
            vec!["group-address"],
        );
        let owner_token = fixture.owner_token.clone();
        let member_token = fixture.member_token.clone();
        let google_source = connect_source(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            "google",
            "personal_mailbox",
            "owner@gmail.example",
            "owner-google-acct",
            "owner-gmail",
            Vec::new(),
        )
        .await;
        let imap_source = connect_source(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            "imap",
            "personal_mailbox",
            "owner@imap.example",
            "owner-imap-acct",
            "owner-imap",
            Vec::new(),
        )
        .await;
        let m365_source = connect_source(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            "microsoft365",
            "personal_mailbox",
            "owner@m365.example",
            "owner-m365-acct",
            "owner-m365",
            Vec::new(),
        )
        .await;
        let member_source = connect_source(
            &fixture,
            &member_token,
            holder_binding(&fixture, &fixture.member_slip),
            "imap",
            "personal_mailbox",
            "member@imap.example",
            "member-imap-acct",
            "member-imap",
            Vec::new(),
        )
        .await;
        let group_source = connect_source(
            &fixture,
            &owner_token,
            owner_binding(&fixture),
            "google",
            "group_address",
            "group@example.com",
            "group-acct",
            "group-mail",
            vec![member_hex.clone()],
        )
        .await;
        let received = fixture.vault.now_recorded_at();
        land_seeds(
            &fixture,
            &google_source,
            vec![seed_message(
                "owner-msg-1",
                "owner-thread-1",
                "Quarterly plan",
                "Can we move the review to Thursday?",
                "owner@gmail.example",
                received,
            )],
        );
        land_seeds(
            &fixture,
            &imap_source,
            vec![seed_message(
                "owner-msg-2",
                "owner-thread-2",
                "Offsite",
                "The offsite moves to March.",
                "owner@imap.example",
                received,
            )],
        );
        land_seeds(
            &fixture,
            &member_source,
            vec![seed_message(
                "member-msg-1",
                "member-thread-1",
                "Thursday rota",
                "The Thursday rota is posted.",
                "member@imap.example",
                received,
            )],
        );
        let (status, page) =
            post_as_owner(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(status, StatusCode::OK, "the owner reads the inbox: {page}");
        let items = page["items"].as_array().expect("the inbox answers items");
        assert_eq!(items.len(), 2, "both owner messages list: {page}");
        let thread_of = |subject: &str| {
            items
                .iter()
                .find(|item| item["subject"].as_str() == Some(subject))
                .unwrap_or_else(|| panic!("the {subject} thread lists: {page}"))
                .get("thread_ref")
                .and_then(Value::as_str)
                .expect("an item names its thread")
                .to_owned()
        };
        let google_thread = thread_of("Quarterly plan");
        let imap_thread = thread_of("Offsite");
        let imap_turn = items
            .iter()
            .find(|item| item["subject"].as_str() == Some("Offsite"))
            .expect("the offsite item lists")["turn_ref"]
            .as_str()
            .expect("an item names its turn")
            .to_owned();
        let (status, member_page) =
            post_as_member(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member reads the inbox: {member_page}"
        );
        let member_thread = thread_ref_by_subject(&member_page, "Thursday rota");
        let (_agent, agent_slip, agent_token) = agent_with_grant(&fixture, "mail_refusal_agent");
        let narrowed_slip =
            mint_narrowed_host_credential(&fixture.owner_slip, &fixture.vault, &fixture.issuer);
        let narrowed_token = narrowed_slip.to_token().expect("narrowed host token");
        let readonly_slip = mint_readonly_credential(
            &fixture.owner_slip,
            &fixture.vault,
            &fixture.issuer,
            fixture.member,
        );
        let readonly_token = readonly_slip.to_token().expect("read-only token");
        let unknown_hex = EntityId::now().to_hex();

        // Row 10 first: the member's read of the owner's thread is 404 (handler audience).
        let (row10_status, row10) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.threads.read",
            json!({"thread_ref": google_thread.clone()}),
        )
        .await;
        assert_refusal(
            row10_status,
            &row10,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail thread by that ref",
        );

        // Row 1: a read-only slip meets the scope guard (facade, before decode).
        let (row1_status, row1) = post_with(
            &fixture,
            "/v1/core/facade/vault.mail.threads.share",
            &readonly_token,
            &readonly_slip,
            json!({"record_ref": google_thread.clone(), "person_ref": member_hex.clone()}),
        )
        .await;
        assert_refusal(
            row1_status,
            &row1,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "request does not have the required scope",
        );

        // Rows 2-4: a narrowed host-holder slip meets each owner precheck.
        let (row2_status, row2) = post_with(
            &fixture,
            "/v1/core/facade/vault.mail.pack.install",
            &narrowed_token,
            &narrowed_slip,
            json!({}),
        )
        .await;
        assert_refusal(
            row2_status,
            &row2,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "vault.mail.pack.install is the vault owner's",
        );
        let (row3_status, row3) = post_with(
            &fixture,
            "/v1/core/facade/vault.mail.sources.sync",
            &narrowed_token,
            &narrowed_slip,
            json!({"source_ref": google_source.clone()}),
        )
        .await;
        assert_refusal(
            row3_status,
            &row3,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "vault.mail.sources.sync is the vault owner's",
        );
        let (row4_status, row4) = post_with(
            &fixture,
            "/v1/core/facade/vault.mail.sources.search",
            &narrowed_token,
            &narrowed_slip,
            json!({"source_ref": google_source.clone(), "query": "x"}),
        )
        .await;
        assert_refusal(
            row4_status,
            &row4,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "vault.mail.sources.search is the vault owner's",
        );

        // Row 5: an agent's approve is refused (status and code only: the served
        // precheck's message changes with the FIX 18868 fix).
        let (row5_status, row5) = post_with(
            &fixture,
            "/v1/core/facade/vault.mail.reply.approve",
            &agent_token,
            &agent_slip,
            json!({"draft_ref": unknown_hex.clone(), "revision": 1}),
        )
        .await;
        assert_eq!(
            row5_status,
            StatusCode::FORBIDDEN,
            "an agent's approve is refused: {row5}"
        );
        assert_eq!(
            row5["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {row5}"
        );

        // Rows 6-7: bodies that do not decode are 400 (facade validate_input).
        let (row6_status, row6) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.inbox",
            json!({"bogus_field": 1}),
        )
        .await;
        assert_eq!(
            row6_status,
            StatusCode::BAD_REQUEST,
            "an unknown field is refused: {row6}"
        );
        assert_eq!(
            row6["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {row6}"
        );
        assert!(
            row6["error"]["message"]
                .as_str()
                .is_some_and(|text| text.starts_with("invalid SDK request: ")),
            "the refusal names the decode: {row6}"
        );
        let (row7_status, row7) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.inbox",
            json!({"limit": "fifty"}),
        )
        .await;
        assert_eq!(
            row7_status,
            StatusCode::BAD_REQUEST,
            "a mistyped field is refused: {row7}"
        );
        assert_eq!(
            row7["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {row7}"
        );
        assert!(
            row7["error"]["message"]
                .as_str()
                .is_some_and(|text| text.starts_with("invalid SDK request: ")),
            "the refusal names the decode: {row7}"
        );

        // Row 8: without the pack, the inbox is refused (handler pack gate).
        let bare = setup().await;
        let (row8_status, row8) =
            post_as_owner(&bare, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_refusal(
            row8_status,
            &row8,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "the Mail & Calendar pack is not installed",
        );

        // Row 9: the member's inbox omits the owner's mailbox (empty, not refusal).
        let (row9_status, row9) =
            post_as_member(&fixture, "/v1/core/facade/vault.mail.inbox", json!({})).await;
        assert_eq!(
            row9_status,
            StatusCode::OK,
            "the member's inbox reads: {row9}"
        );
        assert!(
            row9["items"]
                .as_array()
                .expect("items")
                .iter()
                .all(|item| item["source_ref"].as_str() == Some(member_source.as_str())),
            "none of the owner's mail lists: {row9}"
        );

        // Row 13: the member's sources list hides the owner's mailboxes.
        let (row13_status, row13) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.sources.list",
            json!({}),
        )
        .await;
        assert_eq!(
            row13_status,
            StatusCode::OK,
            "the member's sources list reads: {row13}"
        );
        assert!(
            !row13.to_string().contains(&google_source),
            "the google mailbox hides: {row13}"
        );
        assert!(
            !row13.to_string().contains(&imap_source),
            "the imap mailbox hides: {row13}"
        );
        assert!(
            !row13.to_string().contains("owner@gmail.example"),
            "no mailbox name leaks: {row13}"
        );

        // One share for row 23's outsider-unshare below.
        let (status, shared) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.threads.share",
            json!({"record_ref": google_thread.clone(), "person_ref": member_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner shares the thread: {shared}"
        );

        // Row 11: an unknown thread reads exactly like an unread one.
        let (row11_status, row11) = post_as_stranger(
            &fixture,
            "/v1/core/facade/vault.mail.threads.read",
            json!({"thread_ref": unknown_hex.clone()}),
        )
        .await;
        assert_refusal(
            row11_status,
            &row11,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail thread by that ref",
        );
        assert_eq!(
            row11["error"]["code"].as_str(),
            row10["error"]["code"].as_str(),
            "unknown and unread threads refuse the same code"
        );
        assert_eq!(
            row11["error"]["message"].as_str(),
            row10["error"]["message"].as_str(),
            "unknown and unread threads refuse the same reason (request_id differs by design)"
        );

        // Row 12: a thread ref that is not hex is 400 (handler hex decode).
        let (row12_status, row12) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.threads.read",
            json!({"thread_ref": "zz"}),
        )
        .await;
        assert_refusal(
            row12_status,
            &row12,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "invalid key or value bytes",
        );

        // Row 14: a member turns compliance search on nowhere (handler admin gate).
        let (row14_status, row14) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.set",
            json!({"enabled": true, "purpose": "audit"}),
        )
        .await;
        assert_refusal(
            row14_status,
            &row14,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "org compliance search is set by the vault's Owner or an Admin",
        );

        // Row 15: a member reads no compliance log (handler admin gate).
        let (row15_status, row15) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.log",
            json!({}),
        )
        .await;
        assert_refusal(
            row15_status,
            &row15,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no compliance log for this reader",
        );

        // Row 16: the owner searches nothing while the setting is off.
        let (row16_status, row16) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.search",
            json!({"query": "x", "purpose": "y"}),
        )
        .await;
        assert_refusal(
            row16_status,
            &row16,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "org compliance search is off, or the caller is not the vault's Owner or an Admin",
        );

        // Row 17: a blank query names no words (setting on for this row only).
        let (status, _) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.set",
            json!({"enabled": true, "purpose": "refusal table"}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner turns the setting on");
        let (row17_status, row17) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.compliance.search",
            json!({"query": "  ", "purpose": "y"}),
        )
        .await;
        assert_refusal(
            row17_status,
            &row17,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "a compliance search names its words",
        );

        // Row 18: a member sets nothing on the owner's source (handler audience).
        let (row18_status, row18) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.sources.settings.set",
            json!({"source_ref": google_source.clone()}),
        )
        .await;
        assert_refusal(
            row18_status,
            &row18,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail source by that ref",
        );

        // Row 19: a personal mailbox has no members to set.
        let (row19_status, row19) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.sources.members.set",
            json!({"source_ref": google_source.clone(), "members": [member_hex.clone()]}),
        )
        .await;
        assert_refusal(
            row19_status,
            &row19,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail source by that ref",
        );

        // Row 20: a group address names at least one member.
        let (row20_status, row20) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.sources.members.set",
            json!({"source_ref": group_source, "members": []}),
        )
        .await;
        assert_refusal(
            row20_status,
            &row20,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "a group address names at least one member",
        );

        // Row 21: a stranger shares no thread it does not read.
        let (row21_status, row21) = post_as_stranger(
            &fixture,
            "/v1/core/facade/vault.mail.threads.share",
            json!({"record_ref": google_thread.clone(), "person_ref": member_hex.clone()}),
        )
        .await;
        assert_refusal(
            row21_status,
            &row21,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail thread by that ref",
        );

        // Row 22: a thread is shared with a live PERSON.
        let (row22_status, row22) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.threads.share",
            json!({"record_ref": google_thread.clone(), "person_ref": unknown_hex.clone()}),
        )
        .await;
        assert_refusal(
            row22_status,
            &row22,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "a thread is shared with a live PERSON",
        );

        // The stranger reads the thread from here on (so row 23 reaches the unshare
        // gate instead of the readability gate); rows 21 and 22 run before this share.
        let (status, _) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.threads.share",
            json!({"record_ref": google_thread.clone(), "person_ref": stranger_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner shares the thread with a stranger"
        );

        // Row 23: a thread reader withdraws no share it is not part of.
        let (row23_status, row23) = post_as_stranger(
            &fixture,
            "/v1/core/facade/vault.mail.threads.unshare",
            json!({"record_ref": google_thread.clone(), "person_ref": member_hex.clone()}),
        )
        .await;
        assert_refusal(
            row23_status,
            &row23,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "a share is withdrawn by a reader of its source, by the person who shared it, \
             or by the person it names",
        );

        // Row 24: a member drafts no reply on a thread it does not read.
        let (row24_status, row24) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": imap_thread.clone(),
                "body": "Hello.",
                "request_key": "t8-unread",
            }),
        )
        .await;
        assert_refusal(
            row24_status,
            &row24,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail thread by that ref",
        );

        // Row 25: a reply body is 1 to 65536 bytes.
        let (row25_status, row25) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": imap_thread.clone(),
                "body": "",
                "request_key": "t8-empty",
            }),
        )
        .await;
        assert_refusal(
            row25_status,
            &row25,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "a reply body is 1 to 65536 bytes",
        );

        // One live draft for rows 26, 28 and 29.
        let (status, live) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": imap_thread.clone(),
                "body": "Thursday works for me.",
                "request_key": "t8-live",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner drafts a reply: {live}");
        let live_ref = live["draft_ref"]
            .as_str()
            .expect("a draft answers its ref")
            .to_owned();

        // Row 26: a stranger discards no live draft.
        let (row26_status, row26) = post_as_stranger(
            &fixture,
            "/v1/core/facade/vault.mail.reply.discard",
            json!({"draft_ref": live_ref.clone()}),
        )
        .await;
        assert_refusal(
            row26_status,
            &row26,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no reply draft by that ref",
        );

        // Row 28 (a member's approve) is dropped: it is refused at the served owner
        // precheck today (FIX 18868 regression; ASK MAIL-REPLY-APPROVE-MEMBER-REFUSED).

        // The handler's own-person gate: the owner approving the member's draft.
        let (status, member_live) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": member_thread,
                "body": "Noted, thanks.",
                "request_key": "t8-member",
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the member drafts on their own mailbox: {member_live}"
        );
        let member_ref = member_live["draft_ref"]
            .as_str()
            .expect("a draft answers its ref")
            .to_owned();
        let (own_status, own_answer) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.approve",
            json!({"draft_ref": member_ref, "revision": 1}),
        )
        .await;
        assert_refusal(
            own_status,
            &own_answer,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "only the mailbox's own person approves its replies",
        );

        // Row 29: a wrong revision is 409.
        let (row29_status, row29) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.approve",
            json!({"draft_ref": live_ref.clone(), "revision": 999}),
        )
        .await;
        assert_refusal(
            row29_status,
            &row29,
            StatusCode::CONFLICT,
            "INVALID_STATE",
            "the draft changed since it was reviewed; review its current revision",
        );

        // Row 30: a discarded draft never sends.
        let (status, doomed) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.draft",
            json!({
                "thread_ref": imap_thread.clone(),
                "body": "On reflection, no.",
                "request_key": "t8-doomed",
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner drafts again: {doomed}");
        let doomed_ref = doomed["draft_ref"]
            .as_str()
            .expect("a draft answers its ref")
            .to_owned();
        let (status, _) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.discard",
            json!({"draft_ref": doomed_ref.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "the owner discards the draft");
        let (row30_status, row30) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.reply.approve",
            json!({"draft_ref": doomed_ref.clone(), "revision": 1}),
        )
        .await;
        assert_refusal(
            row30_status,
            &row30,
            StatusCode::CONFLICT,
            "INVALID_STATE",
            "the draft was discarded; it never sends",
        );

        // Row 31: a member opens no attachment on the owner's turn.
        let (row31_status, row31) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.attachments.open",
            json!({
                "source_ref": imap_source.clone(),
                "turn_ref": imap_turn.clone(),
                "part_id": "1",
            }),
        )
        .await;
        assert_refusal(
            row31_status,
            &row31,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no attachment by that ref",
        );

        // Row 32: the message has no such attachment.
        let (row32_status, row32) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.attachments.open",
            json!({
                "source_ref": imap_source.clone(),
                "turn_ref": imap_turn.clone(),
                "part_id": "no-such-part",
            }),
        )
        .await;
        assert_refusal(
            row32_status,
            &row32,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "the message has no such attachment, or its body has not landed yet",
        );

        // Row 33: a member reads no sync status on the owner's source.
        let (row33_status, row33) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.sources.sync_status",
            json!({"source_ref": google_source.clone()}),
        )
        .await;
        assert_refusal(
            row33_status,
            &row33,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail source by that ref",
        );

        // Row 34: a member reads no audience events on the owner's source.
        let (row34_status, row34) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.sources.audience_events",
            json!({"source_ref": google_source.clone()}),
        )
        .await;
        assert_refusal(
            row34_status,
            &row34,
            StatusCode::NOT_FOUND,
            "NOT_FOUND",
            "no mail source by that ref",
        );

        // Row 35: the mbox file goes by its absolute path. The served owner
        // passes the handler's embedded-owner proof, so this 400 is the
        // path check's, not an owner refusal.
        let (row35_status, row35) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.sources.import_mbox",
            json!({"source_ref": google_source.clone(), "path": "rel.mbox"}),
        )
        .await;
        assert_refusal(
            row35_status,
            &row35,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "name the mbox file by its absolute path",
        );

        // Row 36: an mbox file imports into a Google or an IMAP mailbox.
        let probe_path = fixture._dir.path().join("probe.mbox");
        std::fs::write(
            &probe_path,
            "From owen@example.com

hello
",
        )
        .expect("the probe mbox file");
        let (row36_status, row36) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.sources.import_mbox",
            json!({
                "source_ref": m365_source,
                "path": probe_path.to_string_lossy(),
            }),
        )
        .await;
        assert_refusal(
            row36_status,
            &row36,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "an mbox file imports into a Google or an IMAP mailbox",
        );

        // Row 37: a member connects no group address.
        let (row37_status, row37) = post_as_member(
            &fixture,
            "/v1/core/facade/vault.mail.sources.connect",
            json!({
                "provider": "google",
                "kind": "group_address",
                "address": "new-group@example.com",
                "provider_account": "new-group-acct",
                "custody_ref": "group-mail",
                "members": [member_hex.clone()],
            }),
        )
        .await;
        assert_refusal(
            row37_status,
            &row37,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "a group address is connected by the vault's Owner or an Admin",
        );

        // Row 38: IMAP carries no calendar (only Imap fails the fit gate).
        let (row38_status, row38) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.sources.connect",
            json!({
                "provider": "imap",
                "kind": "calendar",
                "address": "cal@example.com",
                "provider_account": "cal-acct",
                "custody_ref": "owner-gmail",
            }),
        )
        .await;
        assert_refusal(
            row38_status,
            &row38,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "imap carries no calendar",
        );

        // Row 39: no credential is stored under an unknown custody name.
        let (row39_status, row39) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.mail.sources.connect",
            json!({
                "provider": "google",
                "kind": "personal_mailbox",
                "address": "ghost@example.com",
                "provider_account": "ghost-acct",
                "custody_ref": "no-such-custody",
            }),
        )
        .await;
        assert_refusal(
            row39_status,
            &row39,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "no credential is stored under this custody name",
        );
    });
}
