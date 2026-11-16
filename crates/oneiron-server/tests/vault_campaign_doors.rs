//! The campaign doors (ARCH-0059), entered as the SDK enters them: HTTP
//! `POST /v1/core/facade/<verb>` through the in-process router (`oneshot`, no
//! TCP ports, no sleeps), plus the one resource route the promises need,
//! `POST /campaigns/{campaign_ref}/launch`, which the same `build_app` mounts.
//!
//! The promises, each with its canon line:
//! P1 "A campaign is a standing, agent-tended program over people"
//! (`generated/llms-full.txt:346835`): a program is created, read, replaced
//! whole under a version check, and archived; the archive sticks, stays
//! readable, and refuses further writes; reads and writes are scoped to the
//! campaign's owner.
//! P2 "an agent launches only under a grant that names campaign launch"
//! (`generated/llms-full.txt:346876`): an agent's launch without that grant is
//! refused, with it the launch lands; a person who owns the campaign always
//! launches. The launch is authenticated by `surface_actor`, which needs a
//! `principal_ref`, so the test launches on person and agent slips, never on
//! the root token (the root carries no principal and is refused).
//! P3 "A campaign unsubscribe → suppression claim, written at once."
//! (`generated/llms-full.txt:347025`): one unsubscribe call answers the
//! suppression claim and the suppressed heads, and a later enroll of that
//! person on that channel is refused. The send-hold half stays unproven: a
//! send after suppression holds at the gate as PENDING, which is not a door
//! answer, so this file asserts the receipt and the enroll refusal only.
//!
//! The file also proves the compliance promise beside P1-P3 (a tightening
//! install applies at once, a loosening waits for the owner's exact-hash
//! stamp, approve and reject land), the held/approve-once owner review, and
//! the family's refusal table. No test and no seeded fault reaches a provider
//! send: every leg drives behind a no-send transport, and approve-once only
//! enqueues its redrive.
//!
//! Each test owns a fresh vault on a `MemoryKeystore` with the CRM pack
//! registered from allocated type bytes. POSTs carry no `x-oneiron-invocation`,
//! so every call runs fresh and nothing replays.
//!
//! Open-PR boundary: #8362 rewrites the send leg, the runner, and
//! `surface/campaign.rs`, so this file asserts receipts, status codes, and
//! messages only there, never leg internals; #8396 adds the one-click wire,
//! which this file does not touch; #8434 rewrites write actors and authorship,
//! which this file never asserts.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_campaign_doors`.
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
use oneiron::attempt_queue::{ClaimOutcome, EnqueueOutcome};
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::campaign::enrollment::{
    CAMPAIGN_ENROLLMENT_SCHEMA_VERSION, CampaignEnrollmentAttemptPayload, CampaignEnrollmentClaim,
    CampaignEnrollmentRunner, CampaignHomeNodeCandidate, CampaignProgramDraft,
    CampaignProgramOutbound, CampaignProgramStepDraft, DetectEnrollment, EnrollmentDetection,
    EnrollmentLegDrive, create_campaign_program, detect_enrollment,
    elect_campaign_home_node_designation,
};
use oneiron::campaign::register_crm_pack;
use oneiron::campaign::surface::{SurfaceCall, invoke_campaign_surface, launch_campaign};
use oneiron::channel_identity::{
    ChannelIdentity, ChannelIdentityBinding, ChannelIdentityFulfillment, ChannelIdentityStep,
    SelfHeldShape,
};
use oneiron::comm::resolve_or_create_comm_party;
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::federation::ScopeAxis;
use oneiron::genui::{GrantMintIntent, GrantMintIntentScope};
use oneiron::outbound_consent::{OutboundResultSender, OutboundTransportResult};
use oneiron::outbound_intent_ledger::FrozenOutboundCall;
use oneiron::registry::{
    ENTITY_TYPE_PERSON, TYPE_BYTE_ZONE_COMPILED_PRODUCT_END, TYPE_BYTE_ZONE_COMPILED_PRODUCT_START,
    TypeByteFamily, allocate_type_byte,
};
use oneiron::saved_query::{
    ClaimComparison, CreateSavedQueryRequest, EvalMode, EvalPolicy, FilterAst, MatcherSpec,
    QueryScope, SAVED_QUERY_SCHEMA_VERSION, SavedQueryEvaluator, create_saved_query,
    sweep_owner_read,
};
use oneiron::store::GateDecisionId;
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig, WriteActor,
};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use tower::ServiceExt;

/// The enrollment leg's home node, as the copy-review fixture names it.
const HOME_NODE: u64 = 11;
/// The held step's durable call sequence.
const CALL_SEQ: u64 = 7;
/// The held step's filed body.
const BODY: &[u8] = b"Hi Yuki, our new plan cuts your costs in half. Reply to book a call.";

struct Fixture {
    vault: Arc<Vault>,
    _dir: tempfile::TempDir,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner: EntityId,
    person: EntityId,
    person_slip: CapabilitySlip,
    person_token: String,
    agent: EntityId,
    agent_slip: CapabilitySlip,
    agent_token: String,
    narrowed_host_slip: CapabilitySlip,
    narrowed_host_token: String,
    readonly_slip: CapabilitySlip,
    readonly_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
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
/// principal and no actor class. The owner root is the full host slip; this
/// narrowed child names no person, so `facade_actor` refuses it.
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

/// A read-only human credential holding `read` only: the Write rows' scope
/// guard refuses it before the body decodes.
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

/// A record-narrowed human credential: the facade's record-scope guard
/// refuses it with the scope message before any door runs.
fn mint_record_narrowed_credential(
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
    claims.records.insert(who.to_hex());
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a record-narrowed credential")
}

/// The CRM pack on freshly allocated type bytes, as the campaign surface
/// oracle registers it on an ordinarily opened vault.
fn register_pack(vault: &Vault) {
    let family = TypeByteFamily::Productivity;
    let mut occupied: Vec<_> = (TYPE_BYTE_ZONE_COMPILED_PRODUCT_START
        ..=TYPE_BYTE_ZONE_COMPILED_PRODUCT_END)
        .filter(|kind| vault.structural_kind_registration(*kind).is_some())
        .collect();
    let campaign_byte = allocate_type_byte(family, &occupied).expect("a campaign type byte");
    occupied.push(campaign_byte);
    let query_byte = allocate_type_byte(family, &occupied).expect("a saved-query type byte");
    register_crm_pack(vault, campaign_byte, query_byte, family).expect("the CRM pack");
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault.prepare_install_signing().expect("install signing");
    register_pack(&vault);
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-campaign-doors".into()),
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
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let who = seed_person(&vault);
    let person_slip = mint_person_credential(&owner_slip, &vault, &issuer, who);
    let person_token = person_slip.to_token().expect("person slip token");
    let agent = seed_person(&vault);
    let agent_slip = mint_agent_credential(&owner_slip, &vault, &issuer, agent);
    let agent_token = agent_slip.to_token().expect("agent slip token");
    let narrowed_host_slip = mint_narrowed_host_credential(&owner_slip, &vault, &issuer);
    let narrowed_host_token = narrowed_host_slip.to_token().expect("narrowed host token");
    let readonly_slip = mint_readonly_credential(&owner_slip, &vault, &issuer, who);
    let readonly_token = readonly_slip.to_token().expect("read-only token");
    let app = build_app(server);
    Fixture {
        vault,
        _dir: dir,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner,
        person: who,
        person_slip,
        person_token,
        agent,
        agent_slip,
        agent_token,
        narrowed_host_slip,
        narrowed_host_token,
        readonly_slip,
        readonly_token,
    }
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

/// One holder-bound credential's proof for its next request.
fn holder_binding(slip: &CapabilitySlip, vault: &Vault) -> String {
    holder_proof(slip, &holder_key(), vault.now_recorded_at())
        .expect("holder proof")
        .to_string()
}

/// One POST through the in-process router, facade or resource route.
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
    let body: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, body)
}

async fn post_as_owner(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.owner_token.clone();
    post(fixture, path, &token, owner_binding(fixture), body).await
}

async fn post_as_person(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.person_token.clone();
    let binding = holder_binding(&fixture.person_slip, &fixture.vault);
    post(fixture, path, &token, binding, body).await
}

async fn post_as_agent(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.agent_token.clone();
    let binding = holder_binding(&fixture.agent_slip, &fixture.vault);
    post(fixture, path, &token, binding, body).await
}

async fn post_as_narrowed_host(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.narrowed_host_token.clone();
    let binding = holder_binding(&fixture.narrowed_host_slip, &fixture.vault);
    post(fixture, path, &token, binding, body).await
}

async fn post_as_readonly(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.readonly_token.clone();
    let binding = holder_binding(&fixture.readonly_slip, &fixture.vault);
    post(fixture, path, &token, binding, body).await
}

/// One POST on a credential a test minted itself (the owner's person slip, a
/// narrowed slip, an unseeded slip).
async fn post_with_credential(
    fixture: &Fixture,
    path: &str,
    slip: &CapabilitySlip,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    post(
        fixture,
        path,
        token,
        holder_binding(slip, &fixture.vault),
        body,
    )
    .await
}

/// `value` as the hex string it must be: `expected_len` lowercase hex digits.
fn hex_string(value: &Value, what: &str, expected_len: usize) -> String {
    let text = value
        .as_str()
        .unwrap_or_else(|| panic!("{what} is a string: {value}"))
        .to_owned();
    assert_eq!(text.len(), expected_len, "{what} has its length: {text}");
    assert!(
        text.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{what} is hex: {text}"
    );
    text
}

/// A campaign owned by `campaign_owner` acting as `class`, through the JSON
/// door, answered as the surface answers it.
fn create_campaign_in(
    vault: &Vault,
    campaign_owner: EntityId,
    class: EdgeActorClass,
    name: &str,
) -> Value {
    let memory = vault.memory(campaign_owner, class);
    invoke_campaign_surface(
        &memory,
        SurfaceCall {
            verb: "self.campaign.create".to_owned(),
            body: json!({"name": name}),
        },
    )
    .expect("create the campaign")
    .body
}

/// Launches `campaign_hex` at `expected_version` as its owner.
fn launch_campaign_in(
    vault: &Vault,
    campaign_owner: EntityId,
    class: EdgeActorClass,
    campaign_hex: &str,
    expected_version: u64,
) {
    let campaign = EntityId::from_hex(campaign_hex).expect("a campaign ref");
    launch_campaign(
        vault,
        campaign_owner,
        class,
        campaign,
        expected_version,
        vault.now_recorded_at(),
    )
    .expect("launch the campaign");
}

/// Archives `campaign_hex` at `expected_version` as its owner.
fn archive_campaign_in(vault: &Vault, campaign_owner: EntityId, campaign_hex: &str, version: u64) {
    let campaign = EntityId::from_hex(campaign_hex).expect("a campaign ref");
    vault
        .memory(campaign_owner, EdgeActorClass::Human)
        .campaign_archive(campaign, version, vault.now_recorded_at())
        .expect("archive the campaign");
}

/// A live email sending identity bound to `identity_owner`.
fn active_sender_identity(vault: &Vault, identity_owner: EntityId, address: &str) -> EntityId {
    let sender = EntityId::now();
    let requested = ChannelIdentity::requested(
        "email",
        address,
        SelfHeldShape::DedicatedAddress,
        ChannelIdentityBinding::actor(identity_owner),
        1,
    );
    let live = requested
        .step(
            ChannelIdentityStep::Bind(ChannelIdentityFulfillment::Api),
            1,
        )
        .expect("bind the sender")
        .step(ChannelIdentityStep::Fulfill, 1)
        .expect("fulfill the sender");
    vault
        .create_channel_identity(&sender, &live)
        .expect("store the sender");
    sender
}

/// One NOTE the tests cite as contact-basis evidence.
fn evidence_note(vault: &Vault, note_owner: EntityId) -> EntityId {
    vault
        .create_note(
            "research",
            "campaign door evidence",
            WriteActor::new(note_owner, EdgeActorClass::Human),
        )
        .expect("file evidence")
}

/// One enroll call on the wire: `member` joins `campaign` on email, with the
/// sender and evidence the door checks.
fn enroll_body(campaign: &str, member: &str, basis: &str, sender: &str) -> Value {
    json!({
        "campaign_ref": campaign,
        "person_ref": member,
        "channels": [{
            "channel": "email",
            "basis_evidence": basis,
            "sender_ref": sender,
        }],
        "evidence_refs": [basis],
    })
}

/// One program step on the wire: email from `sender_hex` on `basis_hex`.
fn program_step_json(step_hex: &str, sender_hex: &str, basis_hex: &str) -> Value {
    json!({
        "step_ref": step_hex,
        "channel": "email",
        "sender_ref": sender_hex,
        "basis_evidence": basis_hex,
    })
}

/// The seniority claim the held fixture's saved query matches on.
fn put_seniority(vault: &Vault, member: EntityId) {
    vault
        .put_claim(
            &EntityId::now(),
            &ClaimBody::new(
                "profile.seniority",
                ClaimSubject::Entity(member),
                rmpv::Value::from("vp"),
                1.0,
                ClaimApprovalStatus::Approved,
                ClaimLifecycleStatus::Active,
            )
            .expect("fixture"),
            TimeRange { start: 1, end: 1 },
            1,
        )
        .expect("the seniority claim");
}

/// A member the held fixture's query matches: a comm PERSON at `address`,
/// with an active contact from the sender.
fn campaign_member(vault: &Vault, sender: EntityId, address: &str) -> EntityId {
    let member = resolve_or_create_comm_party(vault, address).expect("the member PERSON");
    put_seniority(vault, member);
    vault
        .create_counterparty_contact(
            &EntityId::now(),
            &CounterpartyContactRecord::user_introduction(sender, address, 1).expect("the contact"),
        )
        .expect("store the contact");
    member
}

/// The held fixture's saved query: members whose seniority is "vp".
fn seniority_query(vault: &Vault, query_owner: EntityId) -> EntityId {
    let filter = FilterAst::Claim {
        predicate: "profile.seniority".to_owned(),
        cmp: ClaimComparison::Eq,
        value: json!("vp"),
    };
    create_saved_query(
        vault,
        query_owner,
        EdgeActorClass::Human,
        &CreateSavedQueryRequest {
            schema_version: SAVED_QUERY_SCHEMA_VERSION,
            scope: QueryScope::default(),
            filter: filter.clone(),
            matcher: MatcherSpec::Hard { expression: filter },
            eval: EvalPolicy {
                mode: EvalMode::Manual,
                max_entities_per_wake: 8,
                max_judges_per_wake: 4,
            },
        },
        1,
    )
    .expect("the saved query")
    .query_ref
}

/// The transport behind the held legs. Every leg here holds at the gate, so
/// a send is a failure.
struct NoSend;

impl OutboundResultSender for NoSend {
    fn send(&mut self, _call: &FrozenOutboundCall) -> OutboundTransportResult {
        panic!("the held fixture holds every send before transport")
    }
}

/// P1: a campaign program is created under its campaign, read back, replaced
/// whole under a version check, and archived; the archive sticks, stays
/// readable, and refuses further writes.
///
/// Canon `generated/llms-full.txt:346835` "A campaign is a standing,
/// agent-tended program over people".
#[test]
fn program_lifecycle_create_read_update_archive() {
    run_on_engine_stack("campaign-program-lifecycle", || async {
        let fixture = setup().await;
        let owner_hex = fixture.owner.to_hex();
        let created = create_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            "door program campaign",
        );
        let campaign_hex = created["campaign_ref"]
            .as_str()
            .expect("a campaign ref")
            .to_owned();
        let sender_hex =
            active_sender_identity(&fixture.vault, fixture.owner, "owen@example.com").to_hex();
        let basis_hex = evidence_note(&fixture.vault, fixture.owner).to_hex();
        let step_hex = EntityId::now().to_hex();

        let (status, program) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({
                "campaign_ref": campaign_hex.clone(),
                "name": "door program",
                "steps": [program_step_json(&step_hex, &sender_hex, &basis_hex)],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner creates a program: {program}");
        assert_eq!(
            program["definition"]["definition_version"].as_u64(),
            Some(1),
            "a created program stands at version 1: {program}"
        );
        assert_eq!(
            program["definition"]["owner_actor"].as_str(),
            Some(owner_hex.as_str()),
            "the program's owner is its campaign's: {program}"
        );
        assert_eq!(
            program["definition"]["lifecycle"].as_str(),
            Some("draft"),
            "the program follows its draft campaign: {program}"
        );
        assert_eq!(
            program["definition"]["name"].as_str(),
            Some("door program"),
            "the create echoes the name: {program}"
        );
        assert_eq!(
            program["definition"]["steps"][0]["step_ref"].as_str(),
            Some(step_hex.as_str()),
            "the create echoes the step: {program}"
        );
        assert_eq!(
            program["definition"]["steps"][0]["channel"].as_str(),
            Some("email"),
            "the create echoes the channel: {program}"
        );
        assert_eq!(
            program["automatic_intake"].as_bool(),
            Some(false),
            "a draft program enrolls no one: {program}"
        );
        let program_hex = hex_string(&program["program_ref"], "program_ref", 32);
        assert_ne!(
            program_hex, campaign_hex,
            "the program is a new identity: {program}"
        );

        let (status, read) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.read",
            json!({"campaign_ref": campaign_hex.clone(), "program_ref": program_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the program: {read}");
        assert_eq!(
            read["found"].as_bool(),
            Some(true),
            "the program reads back found: {read}"
        );
        assert_eq!(
            read["record"]["definition"]["definition_version"].as_u64(),
            Some(1),
            "the read echoes version 1: {read}"
        );

        let (status, updated) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.update",
            json!({
                "campaign_ref": campaign_hex.clone(),
                "program_ref": program_hex.clone(),
                "expected_definition_version": 1,
                "name": "door program tended",
                "steps": [program_step_json(&step_hex, &sender_hex, &basis_hex)],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner replaces the program: {updated}"
        );
        assert_eq!(
            updated["definition"]["definition_version"].as_u64(),
            Some(2),
            "the replacement bumps the version: {updated}"
        );
        assert_eq!(
            updated["definition"]["name"].as_str(),
            Some("door program tended"),
            "the replacement renames: {updated}"
        );

        let (status, archived) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.archive",
            json!({
                "campaign_ref": campaign_hex.clone(),
                "program_ref": program_hex.clone(),
                "expected_definition_version": 2,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner archives the program: {archived}"
        );
        assert_eq!(
            archived["definition"]["lifecycle"].as_str(),
            Some("archived"),
            "the archive lands: {archived}"
        );
        assert_eq!(
            archived["definition"]["definition_version"].as_u64(),
            Some(3),
            "the archive bumps the version: {archived}"
        );

        let (status, reread) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.read",
            json!({"campaign_ref": campaign_hex.clone(), "program_ref": program_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the archived program stays readable: {reread}"
        );
        assert_eq!(
            reread["record"]["definition"]["lifecycle"].as_str(),
            Some("archived"),
            "the read shows the archive: {reread}"
        );

        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.update",
            json!({
                "campaign_ref": campaign_hex.clone(),
                "program_ref": program_hex.clone(),
                "expected_definition_version": 3,
                "name": "door program reopened",
                "steps": [program_step_json(&step_hex, &sender_hex, &basis_hex)],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an archived program is read-only: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("invalid config: an archived campaign program is read-only"),
            "the refusal names its reason: {refused}"
        );
    });
}

/// P1, cohort ownership: a program reads only under its campaign's owner. A
/// stranger reads `found: false` and cannot create under the owner's
/// campaign; unknown campaigns read absent and unknown senders are refused.
///
/// Canon `generated/llms-full.txt:346835` "A campaign is a standing,
/// agent-tended program over people".
#[test]
fn program_reads_are_owner_scoped() {
    run_on_engine_stack("campaign-program-scoping", || async {
        let fixture = setup().await;
        let created = create_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            "scoped program campaign",
        );
        let campaign_hex = created["campaign_ref"]
            .as_str()
            .expect("a campaign ref")
            .to_owned();
        let sender_hex =
            active_sender_identity(&fixture.vault, fixture.owner, "owen@example.com").to_hex();
        let basis_hex = evidence_note(&fixture.vault, fixture.owner).to_hex();
        let step_hex = EntityId::now().to_hex();
        let stranger = seed_person(&fixture.vault);
        let stranger_slip = mint_person_credential(
            &fixture.owner_slip,
            &fixture.vault,
            &fixture.issuer,
            stranger,
        );
        let stranger_token = stranger_slip.to_token().expect("stranger slip token");
        let stranger_sender_hex =
            active_sender_identity(&fixture.vault, stranger, "stranger@example.com").to_hex();
        let stranger_basis_hex = evidence_note(&fixture.vault, stranger).to_hex();

        let (status, program) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({
                "campaign_ref": campaign_hex.clone(),
                "name": "scoped program",
                "steps": [program_step_json(&step_hex, &sender_hex, &basis_hex)],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner creates a program: {program}");
        let program_hex = hex_string(&program["program_ref"], "program_ref", 32);

        let (status, read) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.read",
            json!({"campaign_ref": campaign_hex.clone(), "program_ref": program_hex.clone()}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the program: {read}");
        assert_eq!(
            read["found"].as_bool(),
            Some(true),
            "the owner's read finds its program: {read}"
        );

        let (status, foreign) = post_with_credential(
            &fixture,
            "/v1/core/facade/vault.campaign.program.read",
            &stranger_slip,
            &stranger_token,
            json!({"campaign_ref": campaign_hex.clone(), "program_ref": program_hex.clone()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a stranger's read answers: {foreign}"
        );
        assert_eq!(
            foreign["found"].as_bool(),
            Some(false),
            "a stranger reads the program as absent: {foreign}"
        );

        let (status, refused) = post_with_credential(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            &stranger_slip,
            &stranger_token,
            json!({
                "campaign_ref": campaign_hex.clone(),
                "name": "stranger program",
                "steps": [program_step_json(
                    &EntityId::now().to_hex(),
                    &stranger_sender_hex,
                    &stranger_basis_hex
                )],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "a stranger cannot create under the owner's campaign: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("entity not found"),
            "ownership is the read: {refused}"
        );

        let (status, absent) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({
                "campaign_ref": EntityId::now().to_hex(),
                "name": "absent campaign program",
                "steps": [program_step_json(
                    &EntityId::now().to_hex(),
                    &sender_hex,
                    &basis_hex
                )],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an unknown campaign answers absent: {absent}"
        );
        assert_eq!(
            absent["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {absent}"
        );

        let (status, invented) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({
                "campaign_ref": campaign_hex.clone(),
                "name": "invented sender program",
                "steps": [program_step_json(
                    &EntityId::now().to_hex(),
                    &EntityId::now().to_hex(),
                    &basis_hex
                )],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "an unknown sender is refused: {invented}"
        );
        assert_eq!(
            invented["error"]["code"].as_str(),
            Some("INVENTED_REFERENCE"),
            "the refusal names its code: {invented}"
        );
        assert_eq!(
            invented["error"]["message"].as_str(),
            Some(
                "the record named at `/steps/0/sender_ref` does not resolve for this \
                 writer; the write was refused and the refusal receipted"
            ),
            "the refusal names its pointer: {invented}"
        );
    });
}

/// P3: one unsubscribe call writes the suppression claim and the suppressed
/// heads at once, and a later enroll of that person on that channel is
/// refused.
///
/// Canon `generated/llms-full.txt:347025` "A campaign unsubscribe →
/// suppression claim, written at once."
#[test]
fn unsubscribe_writes_suppression_and_enroll_refuses_after() {
    run_on_engine_stack("campaign-unsubscribe", || async {
        let fixture = setup().await;
        let created = create_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            "suppression campaign",
        );
        let campaign_hex = created["campaign_ref"]
            .as_str()
            .expect("a campaign ref")
            .to_owned();
        let campaign_version = created["definition"]["definition_version"]
            .as_u64()
            .expect("a campaign version");
        launch_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            &campaign_hex,
            campaign_version,
        );
        let member_hex = seed_person(&fixture.vault).to_hex();
        let basis_hex = evidence_note(&fixture.vault, fixture.owner).to_hex();
        let sender_hex =
            active_sender_identity(&fixture.vault, fixture.owner, "owen@example.com").to_hex();

        let (status, enrolled) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.enroll",
            enroll_body(&campaign_hex, &member_hex, &basis_hex, &sender_hex),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner enrolls the member: {enrolled}"
        );
        assert_eq!(
            enrolled["state"].as_str(),
            Some("enrolled"),
            "the enroll lands enrolled: {enrolled}"
        );
        assert_eq!(
            enrolled["person_ref"].as_str(),
            Some(member_hex.as_str()),
            "the receipt names the person: {enrolled}"
        );
        assert_eq!(
            enrolled["channels"][0]["channel"].as_str(),
            Some("email"),
            "the receipt names the channel: {enrolled}"
        );
        let membership_hex = hex_string(&enrolled["membership_claim_ref"], "membership", 32);

        let (status, unsubscribed) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.unsubscribe",
            json!({
                "campaign_ref": campaign_hex.clone(),
                "person_ref": member_hex.clone(),
                "channel": "email",
                "evidence_ref": basis_hex.clone(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner unsubscribes the member: {unsubscribed}"
        );
        assert_eq!(
            unsubscribed["channel"].as_str(),
            Some("email"),
            "the receipt names the channel: {unsubscribed}"
        );
        let suppression_hex = hex_string(&unsubscribed["suppression_claim_ref"], "suppression", 32);
        assert_ne!(
            suppression_hex, membership_hex,
            "the suppression is its own claim: {unsubscribed}"
        );
        assert_eq!(
            unsubscribed["receipt_ref"].as_str(),
            Some(format!("claim:{suppression_hex}").as_str()),
            "the receipt names the suppression claim: {unsubscribed}"
        );
        let heads = unsubscribed["member_claim_refs"]
            .as_array()
            .expect("suppressed heads");
        assert_eq!(
            heads.len(),
            1,
            "the one live head is suppressed: {unsubscribed}"
        );
        let head_hex = hex_string(&heads[0], "suppressed head", 32);
        assert_ne!(
            head_hex, membership_hex,
            "the suppressed head replaces the enroll head: {unsubscribed}"
        );
        assert_ne!(
            head_hex, suppression_hex,
            "the suppressed head is not the suppression claim: {unsubscribed}"
        );

        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.enroll",
            enroll_body(&campaign_hex, &member_hex, &basis_hex, &sender_hex),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the suppressed channel refuses the next enroll: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("invalid claim body: suppression forbids campaign enrollment on this channel"),
            "the refusal names the suppression: {refused}"
        );
    });
}

/// P2: an agent launches only under a grant that names campaign launch, at
/// the resource route `POST /campaigns/{campaign_ref}/launch`. A person who
/// owns the campaign always launches. The route authenticates through
/// `surface_actor`, which needs a `principal_ref`: the test launches on
/// person and agent slips, never on the root token, which carries no
/// principal and is refused.
///
/// Canon `generated/llms-full.txt:346876` "an agent launches only under a
/// grant that names campaign launch".
#[test]
fn agent_launch_needs_a_grant_person_needs_none() {
    run_on_engine_stack("campaign-launch-grant", || async {
        let fixture = setup().await;
        let owner_hex = fixture.owner.to_hex();
        let agent_hex = fixture.agent.to_hex();
        let owner_person_slip = mint_person_credential(
            &fixture.owner_slip,
            &fixture.vault,
            &fixture.issuer,
            fixture.owner,
        );
        let owner_person_token = owner_person_slip.to_token().expect("owner person token");
        let owned = create_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            "person launch campaign",
        );
        let owned_hex = owned["campaign_ref"]
            .as_str()
            .expect("a campaign ref")
            .to_owned();
        let owned_version = owned["definition"]["definition_version"]
            .as_u64()
            .expect("a campaign version");
        let agent_owned = create_campaign_in(
            &fixture.vault,
            fixture.agent,
            EdgeActorClass::Agent,
            "agent launch campaign",
        );
        let agent_campaign_hex = agent_owned["campaign_ref"]
            .as_str()
            .expect("a campaign ref")
            .to_owned();
        let agent_campaign_version = agent_owned["definition"]["definition_version"]
            .as_u64()
            .expect("a campaign version");

        let (status, launched) = post_with_credential(
            &fixture,
            &format!("/campaigns/{owned_hex}/launch"),
            &owner_person_slip,
            &owner_person_token,
            json!({"expected_definition_version": owned_version}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "a person launches the campaign it owns: {launched}"
        );
        assert_eq!(
            launched["verb"].as_str(),
            Some("self.campaign.launch"),
            "the reply names its verb: {launched}"
        );
        assert_eq!(
            launched["body"]["definition"]["lifecycle"].as_str(),
            Some("active"),
            "the person's launch lands active: {launched}"
        );
        assert_eq!(
            launched["body"]["definition"]["owner_actor"].as_str(),
            Some(owner_hex.as_str()),
            "the launch keeps the owner: {launched}"
        );

        let (status, refused) = post_as_agent(
            &fixture,
            &format!("/campaigns/{agent_campaign_hex}/launch"),
            json!({"expected_definition_version": agent_campaign_version}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an agent without a grant is refused: {refused}"
        );
        assert_eq!(
            refused["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["message"].as_str(),
            Some("invalid config: campaign launch requires a grant naming campaign launch"),
            "the refusal names the missing grant: {refused}"
        );

        let (status, foreign) = post_as_agent(
            &fixture,
            &format!("/campaigns/{owned_hex}/launch"),
            json!({"expected_definition_version": 2}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an agent reads another's campaign as absent: {foreign}"
        );
        assert_eq!(
            foreign["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {foreign}"
        );
        assert_eq!(
            foreign["message"].as_str(),
            Some("campaign_surface was not found"),
            "ownership is the read: {foreign}"
        );

        let (status, rootless) = post_as_owner(
            &fixture,
            &format!("/campaigns/{agent_campaign_hex}/launch"),
            json!({"expected_definition_version": agent_campaign_version}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "the root token names no principal: {rootless}"
        );
        assert_eq!(
            rootless["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {rootless}"
        );
        assert_eq!(
            rootless["message"].as_str(),
            Some("campaign and saved-query records are owned by an authenticated principal"),
            "the route needs a principal: {rootless}"
        );

        let owner_proof = fixture
            .vault
            .authenticate_owner(
                fixture.owner,
                &fixture.owner.to_hex(),
                true,
                GateDecisionId::now(),
            )
            .expect("an owner proof");
        fixture
            .vault
            .mint_standing_outbound_grant(
                &owner_proof,
                EntityId::now(),
                &GrantMintIntent {
                    principal_ref: agent_hex.clone(),
                    origin_component_id: "vault-campaign-doors".to_owned(),
                    origin_action_id: "launch-grant".to_owned(),
                    origin_receipt_ref: None,
                    scope: GrantMintIntentScope::BriefVerbClass {
                        brief_ref: agent_campaign_hex.clone(),
                        verb_class: "launch".to_owned(),
                    },
                },
            )
            .expect("mint the launch grant");

        let (status, granted) = post_as_agent(
            &fixture,
            &format!("/campaigns/{agent_campaign_hex}/launch"),
            json!({"expected_definition_version": agent_campaign_version}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the grant names the launch, so it lands: {granted}"
        );
        assert_eq!(
            granted["body"]["definition"]["lifecycle"].as_str(),
            Some("active"),
            "the granted launch lands active: {granted}"
        );
        assert_eq!(
            granted["body"]["definition"]["owner_actor"].as_str(),
            Some(agent_hex.as_str()),
            "the launch keeps the agent owner: {granted}"
        );
    });
}

/// Compliance beside P1-P3: a tightening install applies at once with a
/// notice, a loosening waits for the owner's exact-hash stamp, and the
/// owner's approve and reject land.
///
/// Canon `generated/llms-full.txt:346835` (the compliance pack the program
/// rides: "a **compliance pack** that encodes law as versioned,
/// agent-amendable rule rows").
#[test]
fn compliance_install_tightening_applies_loosening_waits_for_owner() {
    run_on_engine_stack("campaign-compliance", || async {
        let fixture = setup().await;
        let owner_hex = fixture.owner.to_hex();

        let (status, first) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.result",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads compliance: {first}");
        let active_pack = first["active"].clone();
        assert_eq!(
            active_pack["pack_version"].as_u64(),
            Some(1),
            "a fresh vault stands on the seed pack: {first}"
        );
        let seed_window = active_pack["verified_at_max_age_secs"]
            .as_u64()
            .expect("the seed trust window");

        let mut tightening = active_pack.clone();
        tightening["pack_version"] = json!(2);
        tightening["verified_at_max_age_secs"] = json!(seed_window - 1);
        let (status, applied) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.install",
            json!({"prior_version": 1, "pack": tightening}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner installs a tightening: {applied}"
        );
        assert_eq!(
            applied["operation"].as_str(),
            Some("install"),
            "the receipt names the install: {applied}"
        );
        assert_eq!(
            applied["disposition"].as_str(),
            Some("applied"),
            "a tightening applies at once: {applied}"
        );
        assert_eq!(
            applied["class"].as_str(),
            Some("Tightening"),
            "the receipt names the class: {applied}"
        );
        assert_eq!(
            applied["effective_version"].as_u64(),
            Some(2),
            "the pack advances: {applied}"
        );

        let (status, second) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.result",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads again: {second}");
        let live_pack = second["active"].clone();
        assert_eq!(
            live_pack["pack_version"].as_u64(),
            Some(2),
            "the tightening is active: {second}"
        );
        let live_window = live_pack["verified_at_max_age_secs"]
            .as_u64()
            .expect("the live trust window");
        let mut loosening = live_pack.clone();
        loosening["pack_version"] = json!(3);
        loosening["verified_at_max_age_secs"] = json!(live_window + 1);
        let (status, staged) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.install",
            json!({"prior_version": 2, "pack": loosening}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner installs a loosening: {staged}"
        );
        assert_eq!(
            staged["disposition"].as_str(),
            Some("pending_owner_stamp"),
            "a loosening waits for the owner stamp: {staged}"
        );
        assert_eq!(
            staged["class"].as_str(),
            Some("LooseningOrAmbiguous"),
            "the receipt names the class: {staged}"
        );
        assert_eq!(
            staged["effective_version"].as_u64(),
            Some(2),
            "a pending loosening changes nothing yet: {staged}"
        );
        let proposal_hex = hex_string(&staged["proposal_hash"], "proposal_hash", 64);

        let (status, pending) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.result",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads pending: {pending}");
        assert_eq!(
            pending["pending"]["proposal_hash"].as_str(),
            Some(proposal_hex.as_str()),
            "the pending proposal is visible: {pending}"
        );

        let (status, stamped) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.approve",
            json!({"prior_version": 2, "proposal_hash": proposal_hex}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner approves the exact hash: {stamped}"
        );
        assert_eq!(
            stamped["operation"].as_str(),
            Some("approve"),
            "the receipt names the approve: {stamped}"
        );
        assert_eq!(
            stamped["disposition"].as_str(),
            Some("applied"),
            "the stamp applies the loosening: {stamped}"
        );
        assert_eq!(
            stamped["effective_version"].as_u64(),
            Some(3),
            "the pack advances: {stamped}"
        );
        assert_eq!(
            stamped["owner_stamp"]["owner_ref"].as_str(),
            Some(owner_hex.as_str()),
            "the stamp names the owner: {stamped}"
        );

        let (status, third) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.result",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads after approve: {third}");
        let stamped_pack = third["active"].clone();
        assert_eq!(
            stamped_pack["pack_version"].as_u64(),
            Some(3),
            "the stamped pack is active: {third}"
        );
        let stamped_window = stamped_pack["verified_at_max_age_secs"]
            .as_u64()
            .expect("the stamped trust window");
        let mut second_loosening = stamped_pack.clone();
        second_loosening["pack_version"] = json!(4);
        second_loosening["verified_at_max_age_secs"] = json!(stamped_window + 1);
        let (status, staged_again) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.install",
            json!({"prior_version": 3, "pack": second_loosening}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner stages a second loosening: {staged_again}"
        );
        assert_eq!(
            staged_again["disposition"].as_str(),
            Some("pending_owner_stamp"),
            "the second loosening waits too: {staged_again}"
        );
        let second_hex = hex_string(&staged_again["proposal_hash"], "proposal_hash", 64);

        let (status, rejected) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.reject",
            json!({"prior_version": 3, "proposal_hash": second_hex}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner rejects the exact hash: {rejected}"
        );
        assert_eq!(
            rejected["operation"].as_str(),
            Some("reject"),
            "the receipt names the reject: {rejected}"
        );
        assert_eq!(
            rejected["disposition"].as_str(),
            Some("rejected"),
            "the reject lands: {rejected}"
        );
        assert_eq!(
            rejected["effective_version"].as_u64(),
            Some(3),
            "a reject changes nothing: {rejected}"
        );

        let (status, last) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.result",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads the last state: {last}");
        assert_eq!(
            last["active"]["pack_version"].as_u64(),
            Some(3),
            "the active pack stands: {last}"
        );
        assert!(
            last["pending"].is_null(),
            "no proposal waits after the reject: {last}"
        );
        assert_eq!(
            last["receipts"].as_array().expect("receipts").len(),
            5,
            "every decision kept its receipt: {last}"
        );
        assert_eq!(
            last["notices"].as_array().expect("notices").len(),
            2,
            "each activation kept its notice: {last}"
        );
    });
}

/// The owner's held review: two legs driven behind a no-send transport list
/// as holds, the exact pair approves once and queues its redrive, and an
/// unknown call ref or a wrong digest is refused. Approve-once only enqueues:
/// it drives no send through any transport.
///
/// Canon `generated/llms-full.txt:346835` ("Sends ride the dispatch gate"):
/// the owner reviews at the door what the gate holds.
#[test]
fn held_lists_and_approve_once_queues_the_redrive() {
    run_on_engine_stack("campaign-held-approve", || async {
        let fixture = setup().await;
        let sender = active_sender_identity(&fixture.vault, fixture.owner, "owen@example.com");
        let query = seniority_query(&fixture.vault, fixture.owner);
        let member_first = campaign_member(&fixture.vault, sender, "yuki@example.com");
        let member_second = campaign_member(&fixture.vault, sender, "ana@example.com");
        let created = create_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            "held review campaign",
        );
        let campaign_hex = created["campaign_ref"]
            .as_str()
            .expect("a campaign ref")
            .to_owned();
        let campaign_version = created["definition"]["definition_version"]
            .as_u64()
            .expect("a campaign version");
        let campaign = EntityId::from_hex(&campaign_hex).expect("a campaign id");
        let step = EntityId::now();
        let program = create_campaign_program(
            &fixture.vault,
            fixture.owner,
            campaign,
            CAMPAIGN_ENROLLMENT_SCHEMA_VERSION,
            &CampaignProgramDraft {
                name: "held review program".to_owned(),
                steps: vec![CampaignProgramStepDraft {
                    step_ref: step,
                    channel: "email".to_owned(),
                    sender_ref: sender,
                    basis_evidence: EntityId::now(),
                    outbound: Some(CampaignProgramOutbound {
                        call_seq: CALL_SEQ,
                        verb: "send".to_owned(),
                        payload: BODY.to_vec(),
                        idempotency_supported: true,
                        subject: Some("A plan for you".to_owned()),
                    }),
                    arm: None,
                }],
                audience: None,
            },
            fixture.vault.now_recorded_at(),
        )
        .expect("the program")
        .program
        .program_ref;
        fixture
            .vault
            .save_campaign_step_body(
                program,
                step,
                CALL_SEQ,
                BODY,
                WriteActor::new(fixture.owner, EdgeActorClass::Human),
                fixture.vault.now_recorded_at(),
            )
            .expect("file the step body");
        launch_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            &campaign_hex,
            campaign_version,
        );
        elect_campaign_home_node_designation(
            &fixture.vault,
            &[CampaignHomeNodeCandidate::always_on_local(HOME_NODE)],
            fixture.vault.now_recorded_at(),
        )
        .expect("the home node");

        let now = fixture.vault.now_recorded_at();
        let read = sweep_owner_read(&fixture.vault, fixture.owner, EdgeActorClass::Human)
            .expect("sweep read")
            .expect("the owner has a usable read");
        let grants = QueryScope::default();
        let evaluator = SavedQueryEvaluator {
            vault: &fixture.vault,
            owner_grants: &grants,
            owner_read: &read,
            judge: None,
        };
        let event_first = match detect_enrollment(
            &evaluator,
            fixture.owner,
            &DetectEnrollment {
                query_ref: query,
                campaign_ref: campaign,
                entity_ref: member_first,
                now: now + 1,
            },
        )
        .await
        .expect("detect the first member")
        {
            EnrollmentDetection::Recorded(event) => *event,
            EnrollmentDetection::NoTransition => panic!("expected a recorded transition"),
        };
        let event_second = match detect_enrollment(
            &evaluator,
            fixture.owner,
            &DetectEnrollment {
                query_ref: query,
                campaign_ref: campaign,
                entity_ref: member_second,
                now: now + 1,
            },
        )
        .await
        .expect("detect the second member")
        {
            EnrollmentDetection::Recorded(event) => *event,
            EnrollmentDetection::NoTransition => panic!("expected a recorded transition"),
        };
        let runner = CampaignEnrollmentRunner::new(&fixture.vault);
        for event in [&event_first, &event_second] {
            match runner
                .enqueue(
                    &CampaignEnrollmentAttemptPayload {
                        membership_event_ref: event.event_ref,
                        campaign_program_ref: program,
                        program_step_ref: step,
                    },
                    None,
                    now + 2,
                )
                .expect("enqueue the attempt")
            {
                EnqueueOutcome::Enqueued(_) | EnqueueOutcome::Existing(_) => {}
                other => panic!("unexpected enqueue outcome: {other:?}"),
            }
        }
        let mut attempts = Vec::new();
        for _ in [0, 1] {
            match runner
                .claim_if_home(HOME_NODE, format!("worker:{HOME_NODE}"), now + 3)
                .expect("claim the attempt")
            {
                CampaignEnrollmentClaim::Queue(ClaimOutcome::Claimed(record)) => {
                    attempts.push(record);
                }
                other => panic!("expected a claim, got {other:?}"),
            }
        }
        let at_ms = (fixture.vault.now_recorded_at() + 4) * 1000;
        for attempt in &attempts {
            let drive = fixture
                .vault
                .drive_enrollment_outbound_leg(HOME_NODE, attempt, &mut NoSend, at_ms)
                .expect("drive the leg");
            assert!(
                matches!(drive, EnrollmentLegDrive::AwaitingApproval { .. }),
                "the leg reaches the gate and holds: {drive:?}"
            );
        }

        let (status, held) =
            post_as_owner(&fixture, "/v1/core/facade/vault.campaign.held", json!({})).await;
        assert_eq!(status, StatusCode::OK, "owner lists the holds: {held}");
        let rows = held.as_array().expect("held rows");
        assert_eq!(rows.len(), 2, "both legs hold: {held}");
        let row_for = |member_hex: &str| {
            rows.iter()
                .find(|row| row["member_ref"].as_str() == Some(member_hex))
                .unwrap_or_else(|| panic!("the member's hold: {held}"))
                .clone()
        };
        let first_hex = member_first.to_hex();
        let second_hex = member_second.to_hex();
        let first_row = row_for(&first_hex);
        let second_row = row_for(&second_hex);
        for row in [&first_row, &second_row] {
            assert_eq!(
                row["campaign_ref"].as_str(),
                Some(campaign_hex.as_str()),
                "the hold names its campaign: {held}"
            );
            assert_eq!(
                row["program_ref"].as_str(),
                Some(program.to_hex().as_str()),
                "the hold names its program: {held}"
            );
            assert_eq!(
                row["step_ref"].as_str(),
                Some(step.to_hex().as_str()),
                "the hold names its step: {held}"
            );
            assert_eq!(
                row["held_at_ms"].as_u64(),
                Some(at_ms),
                "the hold names its instant: {held}"
            );
            hex_string(&row["call_ref"], "call_ref", 32);
            hex_string(&row["approval_digest"], "approval_digest", 64);
            assert!(
                row["approved_redrive"].is_null(),
                "nothing redrove yet: {held}"
            );
        }
        let first_call = first_row["call_ref"]
            .as_str()
            .expect("a call ref")
            .to_owned();
        let first_digest = first_row["approval_digest"]
            .as_str()
            .expect("a digest")
            .to_owned();
        let second_call = second_row["call_ref"]
            .as_str()
            .expect("a call ref")
            .to_owned();
        let second_digest = second_row["approval_digest"]
            .as_str()
            .expect("a digest")
            .to_owned();
        assert_ne!(first_call, second_call, "each hold is its own call: {held}");

        let (status, approved) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.approve_once",
            json!({"call_ref": first_call, "approval_digest": first_digest}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the exact pair approves once: {approved}"
        );
        assert_eq!(
            approved["outcome"].as_str(),
            Some("approved"),
            "the receipt names its outcome: {approved}"
        );
        assert_eq!(
            approved["reason_code"].as_str(),
            Some("gate.consent.approve_once"),
            "the receipt names its reason: {approved}"
        );
        assert!(
            approved["decision_ref"].is_string(),
            "the receipt names its decision: {approved}"
        );

        let (status, wrong) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.approve_once",
            json!({"call_ref": second_call, "approval_digest": "0".repeat(64)}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a wrong digest is refused: {wrong}"
        );
        assert_eq!(
            wrong["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {wrong}"
        );
        assert_eq!(
            wrong["error"]["message"].as_str(),
            Some("campaign held digest"),
            "the refusal names the digest: {wrong}"
        );
        assert_ne!(
            "0".repeat(64),
            second_digest,
            "the wrong digest differs from the held one"
        );

        let (status, unknown) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.approve_once",
            json!({"call_ref": EntityId::now().to_hex(), "approval_digest": second_digest}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unknown call is refused: {unknown}"
        );
        assert_eq!(
            unknown["error"]["code"].as_str(),
            Some("BAD_REQUEST"),
            "the refusal names its code: {unknown}"
        );
        assert_eq!(
            unknown["error"]["message"].as_str(),
            Some("campaign held call"),
            "the refusal names the call: {unknown}"
        );

        let (status, relisted) =
            post_as_owner(&fixture, "/v1/core/facade/vault.campaign.held", json!({})).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner relists the holds: {relisted}"
        );
        let again = relisted.as_array().expect("held rows");
        let first_again = again
            .iter()
            .find(|row| row["member_ref"].as_str() == Some(first_hex.as_str()))
            .expect("the approved hold");
        let second_again = again
            .iter()
            .find(|row| row["member_ref"].as_str() == Some(second_hex.as_str()))
            .expect("the waiting hold");
        assert!(
            first_again["approved_redrive"].is_string(),
            "the approve queued its redrive: {relisted}"
        );
        assert!(
            second_again["approved_redrive"].is_null(),
            "the refused hold waits still: {relisted}"
        );
    });
}

/// The family refusal table: owner doors refuse non-owners, unbound callers
/// are refused before the body decodes, the scope guards refuse narrowed
/// credentials, and malformed or unknown records are refused with their own
/// codes. Host-door rows send bodies that decode; plain rows run
/// `facade_actor` before the decode. The `actor_class` "host" mint is
/// refused at the mint, never served. Labels skip A8 (wrong-digest approve,
/// proven by the held test), B9 (stranger create, proven by the scoping
/// test), B14 (suppressed enroll, proven by the unsubscribe test), and
/// B19-B21 (`stage.evidence`, deferred: no promise names it).
///
/// Canon `generated/llms-full.txt:346835`, `:346876`, `:347025`: the doors
/// the promises ride refuse everyone they do not admit, naming why.
#[test]
fn refusal_table() {
    run_on_engine_stack("campaign-refusals", || async {
        let fixture = setup().await;
        let draft = create_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            "refusal draft campaign",
        );
        let draft_hex = draft["campaign_ref"].as_str().expect("a ref").to_owned();
        let live = create_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            "refusal live campaign",
        );
        let live_hex = live["campaign_ref"].as_str().expect("a ref").to_owned();
        let live_version = live["definition"]["definition_version"]
            .as_u64()
            .expect("a version");
        launch_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            &live_hex,
            live_version,
        );
        let retired = create_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            "refusal retired campaign",
        );
        let retired_hex = retired["campaign_ref"].as_str().expect("a ref").to_owned();
        let retired_version = retired["definition"]["definition_version"]
            .as_u64()
            .expect("a version");
        launch_campaign_in(
            &fixture.vault,
            fixture.owner,
            EdgeActorClass::Human,
            &retired_hex,
            retired_version,
        );
        archive_campaign_in(
            &fixture.vault,
            fixture.owner,
            &retired_hex,
            retired_version + 1,
        );
        let member_hex = seed_person(&fixture.vault).to_hex();
        let basis_hex = evidence_note(&fixture.vault, fixture.owner).to_hex();
        let sender_hex =
            active_sender_identity(&fixture.vault, fixture.owner, "owen@example.com").to_hex();
        let ghost = EntityId::now();
        let ghost_slip =
            mint_person_credential(&fixture.owner_slip, &fixture.vault, &fixture.issuer, ghost);
        let ghost_token = ghost_slip.to_token().expect("ghost slip token");
        let narrowed_slip = mint_record_narrowed_credential(
            &fixture.owner_slip,
            &fixture.vault,
            &fixture.issuer,
            fixture.person,
        );
        let narrowed_token = narrowed_slip.to_token().expect("narrowed slip token");

        let (status, first) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.result",
            json!({}),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner reads compliance: {first}");
        let seed_pack = first["active"].clone();

        let (status, program) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({
                "campaign_ref": live_hex.clone(),
                "name": "refusal program",
                "steps": [program_step_json(
                    &EntityId::now().to_hex(),
                    &sender_hex,
                    &basis_hex
                )],
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "owner creates a program: {program}");
        let program_hex = hex_string(&program["program_ref"], "program_ref", 32);

        // A1: the owner host doors refuse a person on a body that decodes.
        for (verb, body) in [
            (
                "vault.campaign.approve_once",
                json!({"call_ref": EntityId::now().to_hex(), "approval_digest": "x"}),
            ),
            ("vault.campaign.held", json!({})),
            (
                "vault.campaign.compliance.install",
                json!({"prior_version": 1, "pack": seed_pack.clone()}),
            ),
        ] {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post_as_person(&fixture, &path, body).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a person is refused {verb}: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("FORBIDDEN"),
                "the refusal names its code: {refused}"
            );
            assert_eq!(
                refused["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "the refusal names the owner: {refused}"
            );
        }

        // A1, agent caller: the approve door refuses an agent too.
        let (status, refused) = post_as_agent(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.approve",
            json!({"prior_version": 1, "proposal_hash": "0".repeat(64)}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an agent is refused the approve door: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("vault.campaign.compliance.approve is the vault owner's"),
            "the refusal names the owner: {refused}"
        );

        // A2: on a caller row the narrowed host-holder is refused before the
        // body decodes, naming the missing principal.
        let (status, refused) = post_as_narrowed_host(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.install",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a narrowed host names no principal: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("facade routes bind writes to an authenticated principal"),
            "the refusal names the missing principal: {refused}"
        );

        // A3: on a non-caller row the narrowed host-holder reaches the owner
        // precheck and is refused as a non-owner.
        for (verb, body) in [
            ("vault.campaign.held", json!({})),
            (
                "vault.campaign.approve_once",
                json!({"call_ref": EntityId::now().to_hex(), "approval_digest": "x"}),
            ),
        ] {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post_as_narrowed_host(&fixture, &path, body).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a narrowed host is refused {verb}: {refused}"
            );
            assert_eq!(
                refused["error"]["message"].as_str(),
                Some(format!("{verb} is the vault owner's")).as_deref(),
                "the refusal names the owner: {refused}"
            );
        }

        // A4: malformed owner bodies are refused by the decode, naming the
        // field that failed.
        for (verb, body) in [
            ("vault.campaign.approve_once", json!({})),
            ("vault.campaign.held", json!({"x": 1})),
            (
                "vault.campaign.compliance.approve",
                json!({"prior_version": 0}),
            ),
        ] {
            let path = format!("/v1/core/facade/{verb}");
            let (status, refused) = post_as_owner(&fixture, &path, body).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "a malformed body is refused at {verb}: {refused}"
            );
            assert_eq!(
                refused["error"]["code"].as_str(),
                Some("BAD_REQUEST"),
                "the refusal names its code: {refused}"
            );
            let message = refused["error"]["message"].as_str().expect("a message");
            assert!(
                message.starts_with("invalid SDK request: "),
                "the decode refuses first: {refused}"
            );
        }

        // A5: a read-only credential is refused a Write row by the scope
        // guard, before the body decodes.
        let (status, refused) = post_as_readonly(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a read-only credential is refused the Write row: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("FORBIDDEN"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("request does not have the required scope"),
            "the refusal names the scope: {refused}"
        );

        // A6: a record-narrowed credential is refused the same way.
        let (status, refused) = post_with_credential(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            &narrowed_slip,
            &narrowed_token,
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a record-narrowed credential is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("request does not have the required scope"),
            "the refusal names the scope: {refused}"
        );

        // A7: an unknown held call is refused without a fixture.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.approve_once",
            json!({"call_ref": EntityId::now().to_hex(), "approval_digest": "x"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unknown held call is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("campaign held call"),
            "the refusal names the call: {refused}"
        );

        // A9: a stale compliance version conflicts before any hash is read.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.approve",
            json!({"prior_version": 999_999, "proposal_hash": "0".repeat(64)}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a stale prior version conflicts: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("prior_version does not match the active compliance pack"),
            "the refusal names the version: {refused}"
        );

        // A10: verification names at least one existing row.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.verify",
            json!({"prior_version": 1, "rows": []}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "empty verification is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("verification names at least one existing row"),
            "the refusal names its reason: {refused}"
        );

        // A11: verification of a rule key that is not active is refused.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.verify",
            json!({
                "prior_version": 1,
                "rows": [{
                    "jurisdiction": "XX",
                    "channel": "email",
                    "rule_kind": "consent_class",
                    "expected_row_version": 1,
                    "source": {
                        "citation": "refusal table",
                        "url": "https://example.test/refusal",
                    },
                    "verified_at": 1_700_000_000u64,
                }],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an unknown rule key is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("verification rule key is not active"),
            "the refusal names its reason: {refused}"
        );

        // A12: a pack without rows cannot validate.
        let mut empty_pack = seed_pack.clone();
        empty_pack["rows"] = json!([]);
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.install",
            json!({"prior_version": 1, "pack": empty_pack}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a rowless pack is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some(
                "invalid config: campaign compliance pack: pack id, warning, and rows must all be \
                 present"
            ),
            "the refusal names its reason: {refused}"
        );

        // `host` is a verb family, never an actor class: no slip mints it.
        let mut host_claims = fixture.owner_slip.claims.clone();
        host_claims.slip_id = next_slip_id();
        host_claims.parent_id = None;
        host_claims.holder_ref = fixture.person.to_hex();
        host_claims.actor_class = Some("host".to_owned());
        host_claims.binding_key = holder_key().verifying_key().to_bytes();
        let host_mint = fixture
            .vault
            .mint_capability_slip(&fixture.issuer, host_claims);
        assert!(host_mint.is_err(), "no slip mints `host` as an actor class");

        // B1: a plain row runs `facade_actor` before the decode, so the
        // narrowed host-holder is refused on any body.
        let (status, refused) = post_as_narrowed_host(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a narrowed host names no principal: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("facade routes bind writes to an authenticated principal"),
            "the refusal names the missing principal: {refused}"
        );

        // B2: a credential whose principal was never seeded is refused by
        // the engine's actor check.
        let (status, refused) = post_with_credential(
            &fixture,
            "/v1/core/facade/vault.campaign.program.read",
            &ghost_slip,
            &ghost_token,
            json!({
                "campaign_ref": live_hex.clone(),
                "program_ref": EntityId::now().to_hex(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "an unseeded principal is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some(format!(
                "bound actor {} does not exist in this vault",
                ghost.to_hex()
            ))
            .as_deref(),
            "the refusal names the missing actor: {refused}"
        );

        // B3: String-typed refs decode, then the hex check refuses them.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.enroll",
            json!({
                "campaign_ref": "zz",
                "person_ref": member_hex.clone(),
                "channels": [],
                "evidence_refs": [],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a non-hex ref is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("campaign references must be 32-character hex entity ids"),
            "the refusal names its reason: {refused}"
        );

        // B4: typed EntityId refs fail the decode instead.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({"campaign_ref": "zz", "name": "untyped"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a non-hex typed ref is refused: {refused}"
        );
        let message = refused["error"]["message"].as_str().expect("a message");
        assert!(
            message.starts_with("invalid SDK request: "),
            "the decode refuses first: {refused}"
        );

        // B5: valid hex that resolves nowhere is an invented reference.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.enroll",
            json!({
                "campaign_ref": EntityId::now().to_hex(),
                "person_ref": member_hex.clone(),
                "channels": [{
                    "channel": "email",
                    "basis_evidence": basis_hex.clone(),
                    "sender_ref": sender_hex.clone(),
                }],
                "evidence_refs": [basis_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "an unknown campaign ref is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("INVENTED_REFERENCE"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some(
                "the record named at `/campaign_ref` does not resolve for this writer; \
                 the write was refused and the refusal receipted"
            ),
            "the refusal names its pointer: {refused}"
        );

        // B6: the program's campaign is not an admitted ref, so an unknown
        // one reads absent at the owned read.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({
                "campaign_ref": EntityId::now().to_hex(),
                "name": "absent campaign program",
                "steps": [program_step_json(
                    &EntityId::now().to_hex(),
                    &sender_hex,
                    &basis_hex
                )],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an unknown campaign answers absent: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("entity not found"),
            "ownership is the read: {refused}"
        );

        // B7: step senders are admitted refs, so an unknown one is refused
        // with its pointer.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({
                "campaign_ref": live_hex.clone(),
                "name": "invented sender program",
                "steps": [program_step_json(
                    &EntityId::now().to_hex(),
                    &EntityId::now().to_hex(),
                    &basis_hex
                )],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "an unknown sender is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some(
                "the record named at `/steps/0/sender_ref` does not resolve for this \
                 writer; the write was refused and the refusal receipted"
            ),
            "the refusal names its pointer: {refused}"
        );

        // B8: an unknown program is not a refusal; it reads unfound.
        let (status, read) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.read",
            json!({
                "campaign_ref": live_hex.clone(),
                "program_ref": EntityId::now().to_hex(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "an unknown program answers: {read}");
        assert_eq!(
            read["found"].as_bool(),
            Some(false),
            "an unknown program reads unfound: {read}"
        );

        // B10: a campaign that is not active cannot enroll.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.enroll",
            json!({
                "campaign_ref": draft_hex,
                "person_ref": member_hex.clone(),
                "channels": [{
                    "channel": "email",
                    "basis_evidence": basis_hex.clone(),
                    "sender_ref": sender_hex.clone(),
                }],
                "evidence_refs": [basis_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a draft campaign cannot enroll: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some(
                "invalid claim body: a campaign that is not active (draft, paused or \
                 archived) cannot enroll"
            ),
            "the refusal names its reason: {refused}"
        );

        // B11: enrollment needs provenance and channel basis evidence.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.enroll",
            json!({
                "campaign_ref": live_hex.clone(),
                "person_ref": member_hex.clone(),
                "channels": [{
                    "channel": "email",
                    "basis_evidence": basis_hex.clone(),
                    "sender_ref": sender_hex.clone(),
                }],
                "evidence_refs": [],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "evidence-free enrollment is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("invalid claim body: enrollment requires provenance and channel basis evidence"),
            "the refusal names its reason: {refused}"
        );

        // B12: membership needs a PERSON; a NOTE resolves but is refused.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.enroll",
            json!({
                "campaign_ref": live_hex.clone(),
                "person_ref": basis_hex.clone(),
                "channels": [{
                    "channel": "email",
                    "basis_evidence": basis_hex.clone(),
                    "sender_ref": sender_hex.clone(),
                }],
                "evidence_refs": [basis_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a non-person subject is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("invalid claim body: campaign membership requires a PERSON"),
            "the refusal names its reason: {refused}"
        );

        // B13: a sender that resolves but is no live channel identity is
        // refused after admission passes it.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.enroll",
            json!({
                "campaign_ref": live_hex.clone(),
                "person_ref": member_hex.clone(),
                "channels": [{
                    "channel": "email",
                    "basis_evidence": basis_hex.clone(),
                    "sender_ref": basis_hex.clone(),
                }],
                "evidence_refs": [basis_hex.clone()],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a non-identity sender is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("invalid claim body: sender_ref is not a live channel identity"),
            "the refusal names its reason: {refused}"
        );

        // B15: an archived campaign's programs are read-only.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.create",
            json!({
                "campaign_ref": retired_hex,
                "name": "retired program",
                "steps": [program_step_json(
                    &EntityId::now().to_hex(),
                    &sender_hex,
                    &basis_hex
                )],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a retired campaign takes no programs: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("invalid config: a campaign's programs are read-only after archive"),
            "the refusal names its reason: {refused}"
        );

        // B16: a stale program version conflicts.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.update",
            json!({
                "campaign_ref": live_hex.clone(),
                "program_ref": program_hex.clone(),
                "expected_definition_version": 999,
                "name": "stale program",
                "steps": [program_step_json(
                    &EntityId::now().to_hex(),
                    &sender_hex,
                    &basis_hex
                )],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "a stale version conflicts: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("INVALID_STATE"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("concurrent write detected: campaign program definition version is not current"),
            "the refusal names its reason: {refused}"
        );

        // B17: an archived program is read-only.
        let (status, archived) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.archive",
            json!({
                "campaign_ref": live_hex.clone(),
                "program_ref": program_hex.clone(),
                "expected_definition_version": 1,
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "owner archives the program: {archived}"
        );
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.program.update",
            json!({
                "campaign_ref": live_hex.clone(),
                "program_ref": program_hex.clone(),
                "expected_definition_version": 2,
                "name": "reopened program",
                "steps": [program_step_json(
                    &EntityId::now().to_hex(),
                    &sender_hex,
                    &basis_hex
                )],
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an archived program is read-only: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("invalid config: an archived campaign program is read-only"),
            "the refusal names its reason: {refused}"
        );

        // B18: unsubscribe needs a PERSON too.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.unsubscribe",
            json!({
                "campaign_ref": live_hex.clone(),
                "person_ref": basis_hex.clone(),
                "channel": "email",
                "evidence_ref": basis_hex.clone(),
            }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a non-person unsubscribe is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("campaign actions require a PERSON"),
            "the refusal names its reason: {refused}"
        );

        // B22: a non-hex receipt ref is refused by the check, not the decode.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.result",
            json!({"receipt_ref": "zz"}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a non-hex receipt ref is refused: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("receipt_ref is a 32-hex receipt id"),
            "the refusal names its reason: {refused}"
        );

        // B23: an unknown receipt reads absent.
        let (status, refused) = post_as_owner(
            &fixture,
            "/v1/core/facade/vault.campaign.compliance.result",
            json!({"receipt_ref": EntityId::now().to_hex()}),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "an unknown receipt answers absent: {refused}"
        );
        assert_eq!(
            refused["error"]["code"].as_str(),
            Some("NOT_FOUND"),
            "the refusal names its code: {refused}"
        );
        assert_eq!(
            refused["error"]["message"].as_str(),
            Some("entity not found"),
            "the refusal names its reason: {refused}"
        );
    });
}
