//! The `vault.weave` doors: recipe admission and parking, schedule CRUD and its role
//! gate, per-reader digests, wrong-label ownership, coachless setting changes,
//! and the fresh-vault refusal table.
//!
//! What this file proves, through `POST /v1/core/facade/<verb>` on the real router:
//! - Admission answers `{state: "queued", existing: false}` and flips the skill
//!   row to Active/Approved; the same refs again answer `{existing: true}` with
//!   the same `job_ref`; the attempt stays `queued` because the server runs no
//!   recipe runtime, so nothing drafts (the ND-040 boundary).
//! - Admission refuses a live non-Candidate skill (400), an unknown skill (404),
//!   and non-hex refs (400).
//! - `schedules.put` / `list` / `clear` round-trip one reader's schedule, and
//!   clearing an unknown reader answers `{cleared: false}`.
//! - `schedules.put` refuses a cross-role recipe (agent + `budgets`, 400) while
//!   the agent + `digest` control put answers 200.
//! - A digest is shown only to its own reader: A's due schedule renders `Some`
//!   over an empty vault and reads back under A, while B and the owner read
//!   `null`, and A's schedule advances past the rendered period.
//! - Wrong labels land through the owner lens on a link and a claim the owner
//!   sees; an agent is refused as no live person, and an absent link is 404.
//! - Without a Coach, `setting_changes.list` answers `[]`, answer/undo of an
//!   unknown change are 404, bad hex is 400, feedback with no owner schedule
//!   is 400, and feedback with one lands and echoes.
//! - The refusal table: owner/person/admin/system/malformed rows refuse with
//!   the door's own status, code and message.
//!
//! Canon oneiron/agents/oneiron-arch-0026-dreamer-v2.md, mirror
//! generated/llms-full.txt:343332 (promise-gate-19): "A weave recipe without a
//! live System read grant is refused before it runs." Admission is not
//! execution: the refusal lives in the wake executor, so this file proves only
//! the boundary (enqueue succeeds and parks). And :343356 (promise-ident-06):
//! "A weave recipe the Owner admitted still leaves its result as a proposal."
//! Weave P2 (:346026, "The weave re-derives arcs from retained spans.") and P3
//! (:343837, "It applies a change directly only when the person's grant names
//! digest settings.", and :344033, "It applies one only under a grant that
//! names digest settings.") stay unproven here (FIX-LIST row WEAVE-PROMISES-UNPROVEN-AT-DOOR).
//!
//! Driving (fixture, router, slips, request helpers) follows the house file
//! `vault_skills_doors.rs`: one form per helper.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test vault_weave_doors`.
//!
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
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole, holder_proof};
use oneiron::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, ClaimSubject,
};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::skill::{SkillLifecycle, SkillRecord};
use oneiron::write_envelope::skill_source::HubFile;
use oneiron::{EdgeActorClass, EdgeKind, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use rmpv::Value as RmpValue;
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
    owner: EntityId,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person_a: EntityId,
    person_a_slip: CapabilitySlip,
    person_a_token: String,
    person_b_slip: CapabilitySlip,
    person_b_token: String,
    agent_person: EntityId,
    agent_slip: CapabilitySlip,
    agent_token: String,
    system_slip: CapabilitySlip,
    system_token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fresh_hex() -> String {
    EntityId::now().to_hex()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key every holder credential here binds; the holder proves it per request.
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

/// A holder credential this host mints `who` under `class`, holding `read` and
/// `write`: a caller's own slip, not owner-grade.
fn mint_credential(
    owner_slip: &CapabilitySlip,
    vault: &Vault,
    issuer: &HostSlipIssuer,
    who: EntityId,
    class: &str,
) -> CapabilitySlip {
    let mut claims = owner_slip.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = who.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.binding_key = holder_key().verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    vault
        .mint_capability_slip(issuer, claims)
        .expect("a credential")
}

/// A Generated Candidate recipe skill with a non-empty SKILL.md, the
/// `dreamer_wake/recipe/tests.rs` shape admission requires.
fn seed_recipe_skill(vault: &Vault, author: EntityId) -> EntityId {
    let skill = EntityId::now();
    let proposal = SkillRecord::new(
        "weave.recipe",
        "One owner-admitted weave",
        "v1",
        ClaimApprovalStatus::Proposed,
        SkillLifecycle::Candidate,
        ClaimSource::Generated,
        0.5,
        true,
        false,
        Vec::new(),
        RmpValue::Map(vec![(RmpValue::from("asked"), RmpValue::from(true))]),
    );
    vault
        .memory(author, EdgeActorClass::Agent)
        .skill_save_with_source(
            skill,
            &proposal,
            vec![HubFile::new(
                "SKILL.md",
                b"---\nname: weave.recipe\n---\nDraft from evidence.\n",
            )],
            None,
            vault.now_recorded_at(),
        )
        .expect("a recipe skill");
    skill
}

/// An Approved, Active claim about the owner, which the owner lens shows.
fn seed_owner_claim(vault: &Vault, owner: EntityId) -> EntityId {
    let claim = EntityId::now();
    let body = ClaimBody::new(
        "report.change",
        ClaimSubject::Entity(owner),
        RmpValue::from("live"),
        1.0,
        ClaimApprovalStatus::Approved,
        ClaimLifecycleStatus::Active,
    )
    .expect("a claim body");
    let now = vault.now_recorded_at();
    vault
        .put_claim(
            &claim,
            &body,
            TimeRange {
                start: now,
                end: now,
            },
            now,
        )
        .expect("an owner-visible claim");
    claim
}

/// A bare `mentions` edge out of the owner, which the owner lens shows.
fn seed_owner_link(vault: &Vault, owner: EntityId, other: EntityId) {
    vault
        .put_edge(&owner, EdgeKind::Mentions, &other, 0.1)
        .expect("an owner-visible link");
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-weave-doors".into()),
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
        .expect("the owner actor");
    let person_a = seed_person(&vault);
    let person_a_slip = mint_credential(&owner_slip, &vault, &issuer, person_a, "human");
    let person_a_token = person_a_slip.to_token().expect("person A slip token");
    let holder_b = seed_person(&vault);
    let person_b_slip = mint_credential(&owner_slip, &vault, &issuer, holder_b, "human");
    let person_b_token = person_b_slip.to_token().expect("person B slip token");
    let agent_person = seed_person(&vault);
    let agent_slip = mint_credential(&owner_slip, &vault, &issuer, agent_person, "agent");
    let agent_token = agent_slip.to_token().expect("agent slip token");
    let holder_system = seed_person(&vault);
    let system_slip = mint_credential(&owner_slip, &vault, &issuer, holder_system, "system");
    let system_token = system_slip.to_token().expect("system slip token");
    let app = build_app(server);
    Fixture {
        vault,
        _dir: dir,
        app,
        issuer,
        owner,
        owner_slip,
        owner_token,
        person_a,
        person_a_slip,
        person_a_token,
        person_b_slip,
        person_b_token,
        agent_person,
        agent_slip,
        agent_token,
        system_slip,
        system_token,
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

async fn post_as_person_a(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.person_a_token.clone();
    let proof = holder_binding(fixture, &fixture.person_a_slip);
    post(fixture, path, &token, proof, body).await
}

async fn post_as_person_b(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.person_b_token.clone();
    let proof = holder_binding(fixture, &fixture.person_b_slip);
    post(fixture, path, &token, proof, body).await
}

async fn post_as_agent(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.agent_token.clone();
    let proof = holder_binding(fixture, &fixture.agent_slip);
    post(fixture, path, &token, proof, body).await
}

async fn post_as_system(fixture: &Fixture, path: &str, body: Value) -> (StatusCode, Value) {
    let token = fixture.system_token.clone();
    let proof = holder_binding(fixture, &fixture.system_slip);
    post(fixture, path, &token, proof, body).await
}

/// The door's own owner refusal: 403 `FORBIDDEN`, naming the verb.
fn assert_owner_refusal(status: StatusCode, body: &Value, verb: &str) {
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
        "{verb} refuses a person: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(format!("{verb} is the vault owner's")).as_deref(),
        "{verb} names its owner: {body}"
    );
}

/// One exact refusal: `what` names the layer that refuses.
fn assert_refusal(
    status: StatusCode,
    body: &Value,
    expected: StatusCode,
    code: &str,
    message: &str,
    what: &str,
) {
    assert_eq!(
        (status, body["error"]["code"].as_str()),
        (expected, Some(code)),
        "{what}: {body}"
    );
    assert_eq!(
        body["error"]["message"].as_str(),
        Some(message),
        "{what}: {body}"
    );
}

#[test]
fn enqueue_admits_and_parks_a_recipe() {
    run_on_engine_stack("weave-enqueue-parks", enqueue_parks_case);
}

/// The admission + parking boundary: admission answers `queued` and flips the
/// skill row, the same refs re-enqueue onto the same job, and the attempt stays
/// queued because the server runs no recipe runtime, so nothing drafts. The
/// ND-040 resume/changed-source pair stays unproven.
async fn enqueue_parks_case() {
    let fixture = setup().await;
    let subject = seed_person(&fixture.vault);
    let evidence = seed_person(&fixture.vault);
    let skill = seed_recipe_skill(&fixture.vault, fixture.agent_person);
    let input = json!({
        "skill_ref": skill.to_hex(),
        "subject_ref": subject.to_hex(),
        "evidence_ref": evidence.to_hex(),
    });
    let (status, admitted) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.enqueue",
        input.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "admission answers: {admitted}");
    assert_eq!(
        admitted["state"].as_str(),
        Some("queued"),
        "a fresh recipe parks queued: {admitted}"
    );
    assert_eq!(
        admitted["existing"].as_bool(),
        Some(false),
        "a fresh recipe is new: {admitted}"
    );
    let job = admitted["job_ref"]
        .as_str()
        .expect("a queued job ref")
        .to_owned();
    assert_eq!(job.len(), 32, "a job ref is 32 hex: {job}");
    let (status, again) =
        post_as_owner(&fixture, "/v1/core/facade/vault.weave.enqueue", input).await;
    assert_eq!(status, StatusCode::OK, "re-enqueue answers: {again}");
    assert_eq!(
        again["existing"].as_bool(),
        Some(true),
        "the same refs coalesce: {again}"
    );
    assert_eq!(
        again["job_ref"].as_str(),
        Some(job.as_str()),
        "the same refs keep the job: {again}"
    );
    assert_eq!(
        again["state"].as_str(),
        Some("queued"),
        "the same refs stay queued: {again}"
    );
    let (status, current) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.consolidation.status",
        json!({"job_ref": &job}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "status answers: {current}");
    assert_eq!(
        current["state"].as_str(),
        Some("queued"),
        "no runtime drafts the parked recipe: {current}"
    );
    assert_eq!(
        current["job_ref"].as_str(),
        Some(job.as_str()),
        "status names the job: {current}"
    );
    let (status, recorded) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.skills.get",
        json!({"entity": skill.to_hex()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the skill reads: {recorded}");
    assert_eq!(
        recorded["lifecycle"].as_str(),
        Some("active"),
        "admission activates the recipe: {recorded}"
    );
    assert_eq!(
        recorded["approval"].as_str(),
        Some("approved"),
        "admission approves the recipe: {recorded}"
    );
}

#[test]
fn enqueue_refuses_a_skill_that_is_not_an_admissible_recipe() {
    run_on_engine_stack("weave-enqueue-refuses", enqueue_refuses_case);
}

/// The admission gate: a live non-Candidate skill is 400, an unknown skill is
/// 404, and non-hex refs are 400 before the engine reads them.
async fn enqueue_refuses_case() {
    let fixture = setup().await;
    let subject = seed_person(&fixture.vault);
    let evidence = seed_person(&fixture.vault);
    let live_skill = seed_recipe_skill(&fixture.vault, fixture.agent_person);
    // The setup admit flips the skill to Active/Approved; assert only its
    // status here, never `existing` (test 1's seeded fault owns that field).
    let (status, _) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.enqueue",
        json!({
            "skill_ref": live_skill.to_hex(),
            "subject_ref": subject.to_hex(),
            "evidence_ref": evidence.to_hex(),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the setup admit lands");
    let fresh_subject = seed_person(&fixture.vault);
    let fresh_evidence = seed_person(&fixture.vault);
    let (status, refused) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.enqueue",
        json!({
            "skill_ref": live_skill.to_hex(),
            "subject_ref": fresh_subject.to_hex(),
            "evidence_ref": fresh_evidence.to_hex(),
        }),
    )
    .await;
    assert_refusal(
        status,
        &refused,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "invalid claim body: invalid or unadmitted per-vault weave recipe",
        "the engine admission gate refuses a live non-Candidate skill",
    );
    let (status, absent) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.enqueue",
        json!({
            "skill_ref": fresh_hex(),
            "subject_ref": subject.to_hex(),
            "evidence_ref": evidence.to_hex(),
        }),
    )
    .await;
    assert_refusal(
        status,
        &absent,
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "entity not found",
        "the engine skill read refuses an unknown skill",
    );
    let (status, malformed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.enqueue",
        json!({
            "skill_ref": "zz",
            "subject_ref": subject.to_hex(),
            "evidence_ref": evidence.to_hex(),
        }),
    )
    .await;
    assert_refusal(
        status,
        &malformed,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "weave inputs name 32-hex entity ids",
        "the verb input mapping refuses non-hex refs",
    );
}

#[test]
fn schedules_put_list_clear_round_trip() {
    run_on_engine_stack("weave-schedules-round-trip", schedules_round_trip_case);
}

/// One reader's schedule lands, lists, clears, and lists empty again; clearing
/// an unknown reader answers `{cleared: false}`.
async fn schedules_round_trip_case() {
    let fixture = setup().await;
    let person_a = fixture.person_a.to_hex();
    let (status, empty) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.list",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a fresh list reads: {empty}");
    assert_eq!(&empty, &json!([]), "a fresh vault holds no schedule");
    // A fixed future instant; no timer runs in the test, so nothing renders.
    let due = 4_100_000_000u64;
    let (status, stored) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.put",
        json!({
            "reader": {"kind": "person", "reader_ref": &person_a},
            "cadence": "daily",
            "next_due_at": due,
            "sections": [{"kind": "changes"}],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a schedule lands: {stored}");
    assert_eq!(
        stored["reader"]["reader_ref"].as_str(),
        Some(person_a.as_str()),
        "the put names its reader: {stored}"
    );
    assert_eq!(
        stored["cadence"].as_str(),
        Some("daily"),
        "the put echoes its cadence: {stored}"
    );
    assert_eq!(
        stored["next_due_at"].as_u64(),
        Some(due),
        "the put echoes its due time: {stored}"
    );
    assert_eq!(
        stored["sections"],
        json!([{"kind": "changes", "predicates": [], "edge_kinds": []}]),
        "the put echoes its recipe: {stored}"
    );
    let (status, listed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.list",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the schedule lists: {listed}");
    assert_eq!(
        listed.as_array().map(Vec::len),
        Some(1),
        "one schedule lists: {listed}"
    );
    assert_eq!(&listed[0], &stored, "the list reads back the put");
    let (status, cleared) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.clear",
        json!({"kind": "person", "reader_ref": &person_a}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a clear answers: {cleared}");
    assert_eq!(
        cleared["cleared"].as_bool(),
        Some(true),
        "clearing a held schedule clears: {cleared}"
    );
    let (status, empty) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.list",
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the list reads after clear: {empty}"
    );
    assert_eq!(&empty, &json!([]), "nothing lists after clear");
    let (status, missing) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.clear",
        json!({"kind": "person", "reader_ref": fresh_hex()}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "clearing unknown answers: {missing}"
    );
    assert_eq!(
        missing["cleared"].as_bool(),
        Some(false),
        "clearing an unknown reader clears nothing: {missing}"
    );
}

#[test]
fn schedules_put_refuses_a_cross_role_recipe() {
    run_on_engine_stack("weave-schedules-cross-role", schedules_cross_role_case);
}

/// The role gate: an agent reader with a `budgets` section is 400, while the
/// agent + `digest` control put lands; a person + `digest` put is 400 too.
async fn schedules_cross_role_case() {
    let fixture = setup().await;
    let agent = fixture.agent_person.to_hex();
    let (status, refused) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.put",
        json!({
            "reader": {"kind": "agent", "reader_ref": &agent},
            "cadence": "daily",
            "next_due_at": 1u64,
            "sections": [{"kind": "budgets"}],
        }),
    )
    .await;
    assert_refusal(
        status,
        &refused,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "invalid config: invalid weave report recipe",
        "the engine role gate refuses an agent budgets recipe",
    );
    let (status, allowed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.put",
        json!({
            "reader": {"kind": "agent", "reader_ref": &agent},
            "cadence": "daily",
            "next_due_at": 1u64,
            "sections": [{"kind": "digest"}],
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the digest control lands: {allowed}"
    );
    assert_eq!(
        allowed["sections"],
        json!([{"kind": "digest", "predicates": [], "edge_kinds": []}]),
        "the control echoes its recipe: {allowed}"
    );
    let (status, refused) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.put",
        json!({
            "reader": {"kind": "person", "reader_ref": fixture.person_a.to_hex()},
            "cadence": "daily",
            "next_due_at": 1u64,
            "sections": [{"kind": "digest"}],
        }),
    )
    .await;
    assert_refusal(
        status,
        &refused,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "invalid config: invalid weave report recipe",
        "the engine role gate refuses a person digest recipe",
    );
}

#[test]
fn digest_is_shown_only_to_its_own_reader() {
    run_on_engine_stack("weave-digest-reader", digest_reader_case);
}

/// Cross-reader isolation: A's due schedule renders `Some` over an empty vault
/// and reads back under A alone; B and the owner hold no schedule and read
/// `null`, and A's schedule advances past the rendered period.
async fn digest_reader_case() {
    let fixture = setup().await;
    let person_a = fixture.person_a.to_hex();
    let (status, stored) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.put",
        json!({
            "reader": {"kind": "person", "reader_ref": &person_a},
            "cadence": "daily",
            "next_due_at": 1u64,
            "sections": [{"kind": "changes"}],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "A's schedule lands: {stored}");
    let (status, rendered) = post_as_person_a(
        &fixture,
        "/v1/core/facade/vault.weave.digest.render",
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "A renders their due period: {rendered}"
    );
    assert_eq!(
        rendered["scheduled_for"].as_u64(),
        Some(1),
        "the render names the due period: {rendered}"
    );
    assert!(
        rendered["rendered_at"].as_u64().is_some_and(|at| at > 1),
        "the render stamps its time: {rendered}"
    );
    let (status, digest) =
        post_as_person_a(&fixture, "/v1/core/facade/vault.weave.digest", json!({})).await;
    assert_eq!(status, StatusCode::OK, "A reads their period: {digest}");
    assert_eq!(
        digest["scheduled_for"].as_u64(),
        Some(1),
        "A reads their own period: {digest}"
    );
    assert_eq!(
        digest["sections"],
        json!([{"kind": "changes", "items": []}]),
        "an empty vault renders the empty section: {digest}"
    );
    let (status, foreign) =
        post_as_person_b(&fixture, "/v1/core/facade/vault.weave.digest", json!({})).await;
    assert_eq!(status, StatusCode::OK, "B's digest reads: {foreign}");
    assert!(foreign.is_null(), "B reads none of A's period: {foreign}");
    let (status, idle) = post_as_person_b(
        &fixture,
        "/v1/core/facade/vault.weave.digest.render",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "B's render reads: {idle}");
    assert!(idle.is_null(), "B renders no period of their own: {idle}");
    let (status, owner_idle) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.owner.digest.render",
        json!({}),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the owner render reads: {owner_idle}"
    );
    assert!(
        owner_idle.is_null(),
        "the owner renders no period of their own: {owner_idle}"
    );
    let (status, listed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.list",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the schedules list: {listed}");
    assert_eq!(
        listed.as_array().map(Vec::len),
        Some(1),
        "only A's schedule stands: {listed}"
    );
    assert_eq!(
        listed[0]["reader"]["reader_ref"].as_str(),
        Some(person_a.as_str()),
        "the standing schedule is A's: {listed}"
    );
    assert!(
        listed[0]["next_due_at"].as_u64().is_some_and(|due| due > 1),
        "A's schedule advanced past the rendered period: {listed}"
    );
}

#[test]
fn owner_labels_land_and_an_agent_is_refused() {
    run_on_engine_stack("weave-labels", labels_case);
}

/// Label ownership: the owner files a link label and a claim label on rows its
/// own lens shows, and the link label reads back; an agent's credential is no
/// live person, and a person naming an absent link meets 404.
async fn labels_case() {
    let fixture = setup().await;
    let owner = fixture.owner.to_hex();
    let other = seed_person(&fixture.vault);
    let other_hex = other.to_hex();
    seed_owner_link(&fixture.vault, fixture.owner, other);
    let link = json!({
        "source_ref": &owner,
        "kind": "mentions",
        "target_ref": &other_hex,
    });
    let (status, filed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.owner.link.wrong",
        link.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the link label lands: {filed}");
    assert_eq!(
        filed["source_ref"].as_str(),
        Some(owner.as_str()),
        "the label names its source: {filed}"
    );
    assert_eq!(
        filed["kind"].as_str(),
        Some("mentions"),
        "the label names its kind: {filed}"
    );
    assert_eq!(
        filed["target_ref"].as_str(),
        Some(other_hex.as_str()),
        "the label names its target: {filed}"
    );
    assert_eq!(
        filed["actor_ref"].as_str(),
        Some(owner.as_str()),
        "the label names the owner: {filed}"
    );
    assert_eq!(
        filed["label_ref"].as_str().map(str::len),
        Some(32),
        "the label mints a ref: {filed}"
    );
    let (status, labels) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.link.corrections",
        link,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the labels read: {labels}");
    assert_eq!(
        labels.as_array().map(Vec::len),
        Some(1),
        "the one label reads back: {labels}"
    );
    assert_eq!(
        labels[0]["label_ref"], filed["label_ref"],
        "the read label is the filed one"
    );
    let claim = seed_owner_claim(&fixture.vault, fixture.owner).to_hex();
    let (status, item) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.owner.item.wrong",
        json!({"item": "claim", "item_ref": &claim}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the claim label lands: {item}");
    assert_eq!(
        item["item"].as_str(),
        Some("claim"),
        "the label names its item: {item}"
    );
    assert_eq!(
        item["item_ref"].as_str(),
        Some(claim.as_str()),
        "the label names its claim: {item}"
    );
    assert_eq!(
        item["actor_ref"].as_str(),
        Some(owner.as_str()),
        "the claim label names the owner: {item}"
    );
    assert!(
        item["project_ref"].is_null(),
        "a claim label names no project: {item}"
    );
    let (status, refused) = post_as_agent(
        &fixture,
        "/v1/core/facade/vault.weave.link.wrong",
        json!({
            "source_ref": &owner,
            "kind": "mentions",
            "target_ref": &other_hex,
        }),
    )
    .await;
    assert_refusal(
        status,
        &refused,
        StatusCode::FORBIDDEN,
        "FORBIDDEN",
        "vault.weave.link.wrong is a live person's own act",
        "the person door refuses an agent's link label",
    );
    let (status, refused) = post_as_agent(
        &fixture,
        "/v1/core/facade/vault.weave.item.wrong",
        json!({"item": "claim", "item_ref": &claim}),
    )
    .await;
    assert_refusal(
        status,
        &refused,
        StatusCode::FORBIDDEN,
        "FORBIDDEN",
        "vault.weave.item.wrong is a live person's own act",
        "the person door refuses an agent's claim label",
    );
    let (status, absent) = post_as_person_a(
        &fixture,
        "/v1/core/facade/vault.weave.link.wrong",
        json!({
            "source_ref": fresh_hex(),
            "kind": "mentions",
            "target_ref": fresh_hex(),
        }),
    )
    .await;
    assert_refusal(
        status,
        &absent,
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "entity not found",
        "the engine visibility check refuses an absent link",
    );
}

#[test]
fn setting_changes_without_a_coach() {
    run_on_engine_stack("weave-setting-changes", setting_changes_case);
}

/// Coachless behavior: no changes list, unknown changes are 404, bad hex is
/// 400, feedback with no owner schedule is 400, and feedback with one lands.
async fn setting_changes_case() {
    let fixture = setup().await;
    let (status, changes) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.setting_changes.list",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the changes list: {changes}");
    assert_eq!(&changes, &json!([]), "no Coach filed a change");
    let unknown = fresh_hex();
    let (status, missing) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.setting_changes.answer",
        json!({"change_ref": &unknown, "accept": true}),
    )
    .await;
    assert_refusal(
        status,
        &missing,
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "entity not found",
        "the engine change read refuses an unknown answer",
    );
    let (status, missing) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.setting_changes.undo",
        json!({"change_ref": &unknown}),
    )
    .await;
    assert_refusal(
        status,
        &missing,
        StatusCode::NOT_FOUND,
        "NOT_FOUND",
        "entity not found",
        "the engine change read refuses an unknown undo",
    );
    let (status, malformed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.setting_changes.answer",
        json!({"change_ref": "zz", "accept": true}),
    )
    .await;
    assert_refusal(
        status,
        &malformed,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "change_ref must be a 32-hex change id",
        "the verb input mapping refuses a bad answer hex",
    );
    let (status, malformed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.setting_changes.undo",
        json!({"change_ref": "zz"}),
    )
    .await;
    assert_refusal(
        status,
        &malformed,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "change_ref must be a 32-hex change id",
        "the verb input mapping refuses a bad undo hex",
    );
    let (status, coachless) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.digest_feedback.put",
        json!({}),
    )
    .await;
    assert_refusal(
        status,
        &coachless,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "invalid config: you have no digest schedule to tell the Coach about",
        "the engine feedback door refuses a scheduleless owner",
    );
    let owner = fixture.owner.to_hex();
    let (status, stored) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.put",
        json!({
            "reader": {"kind": "owner", "reader_ref": owner},
            "cadence": "daily",
            "next_due_at": 1u64,
            "sections": [{"kind": "links"}],
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "the owner schedule lands: {stored}");
    let (status, echoed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.digest_feedback.put",
        json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "feedback lands: {echoed}");
    assert_eq!(
        echoed["keep_current"].as_bool(),
        Some(false),
        "feedback echoes its keep flag: {echoed}"
    );
    let (status, led) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.digest_feedback.put",
        json!({"lead_section": "links"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "a lead section lands: {led}");
    assert_eq!(
        led["lead_section"].as_str(),
        Some("links"),
        "feedback echoes its lead section: {led}"
    );
}

#[test]
fn fresh_vault_refusal_table() {
    run_on_engine_stack("weave-refusal-table", refusal_table_case);
}

/// The gates: the 11 owner doors refuse a person, the person doors refuse an
/// agent, the lens family refuses a system actor, the admin doors refuse an
/// unstepped caller and a malformed grant, and malformed bodies refuse at
/// their own layer. No engine-behavior rows.
async fn refusal_table_case() {
    let fixture = setup().await;
    let person = fixture.person_a.to_hex();
    // W1: each of the 11 owner doors refuses a person with a body that decodes.
    let owner_calls = [
        (
            "vault.weave.enqueue",
            json!({
                "skill_ref": fresh_hex(),
                "subject_ref": fresh_hex(),
                "evidence_ref": fresh_hex(),
            }),
        ),
        (
            "vault.weave.schedules.put",
            json!({
                "reader": {"kind": "person", "reader_ref": person.clone()},
                "cadence": "daily",
                "next_due_at": 1u64,
                "sections": [{"kind": "changes"}],
            }),
        ),
        (
            "vault.weave.schedules.clear",
            json!({"kind": "person", "reader_ref": person.clone()}),
        ),
        ("vault.weave.schedules.list", json!({})),
        (
            "vault.weave.setting_changes.answer",
            json!({"change_ref": fresh_hex(), "accept": true}),
        ),
        (
            "vault.weave.setting_changes.undo",
            json!({"change_ref": fresh_hex()}),
        ),
        ("vault.weave.setting_changes.list", json!({})),
        ("vault.weave.digest_feedback.put", json!({})),
        ("vault.weave.owner.digest.render", json!({})),
        (
            "vault.weave.owner.item.wrong",
            json!({"item": "claim", "item_ref": fresh_hex()}),
        ),
        (
            "vault.weave.owner.link.wrong",
            json!({
                "source_ref": fresh_hex(),
                "kind": "mentions",
                "target_ref": fresh_hex(),
            }),
        ),
    ];
    for (verb, input) in owner_calls {
        let path = format!("/v1/core/facade/{verb}");
        let (status, body) = post_as_person_a(&fixture, &path, input).await;
        assert_owner_refusal(status, &body, verb);
    }
    // W2: the person doors refuse an agent.
    let (status, refused) = post_as_agent(
        &fixture,
        "/v1/core/facade/vault.weave.link.wrong",
        json!({
            "source_ref": fresh_hex(),
            "kind": "mentions",
            "target_ref": fresh_hex(),
        }),
    )
    .await;
    assert_refusal(
        status,
        &refused,
        StatusCode::FORBIDDEN,
        "FORBIDDEN",
        "vault.weave.link.wrong is a live person's own act",
        "the person door refuses an agent",
    );
    let (status, refused) = post_as_agent(
        &fixture,
        "/v1/core/facade/vault.weave.item.wrong",
        json!({"item": "claim", "item_ref": fresh_hex()}),
    )
    .await;
    assert_refusal(
        status,
        &refused,
        StatusCode::FORBIDDEN,
        "FORBIDDEN",
        "vault.weave.item.wrong is a live person's own act",
        "the person door refuses an agent's item label",
    );
    // W3: the lens family refuses a system actor in the engine reader.
    let system_calls = [
        ("vault.weave.report", json!({"sections": []})),
        ("vault.weave.digest.render", json!({})),
        ("vault.weave.digest", json!({})),
        (
            "vault.weave.link.corrections",
            json!({
                "source_ref": fresh_hex(),
                "kind": "mentions",
                "target_ref": fresh_hex(),
            }),
        ),
    ];
    for (verb, input) in system_calls {
        let path = format!("/v1/core/facade/{verb}");
        let (status, body) = post_as_system(&fixture, &path, input).await;
        assert_refusal(
            status,
            &body,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "a system actor reads no weave lens",
            "the engine reader refuses a system actor",
        );
    }
    // W4: the admin doors refuse a caller with no step-up.
    let grant = fresh_hex();
    let admin_calls = [
        (
            "vault.weave.admin.report",
            json!({"membership_grant": grant.clone()}),
        ),
        (
            "vault.weave.admin.lens",
            json!({"membership_grant": grant.clone()}),
        ),
        (
            "vault.weave.admin.digest",
            json!({"membership_grant": grant.clone()}),
        ),
        (
            "vault.weave.admin.link.wrong",
            json!({
                "membership_grant": grant.clone(),
                "request": {
                    "source_ref": fresh_hex(),
                    "kind": "mentions",
                    "target_ref": fresh_hex(),
                },
            }),
        ),
        (
            "vault.weave.admin.item.wrong",
            json!({
                "membership_grant": grant.clone(),
                "request": {"item": "claim", "item_ref": fresh_hex()},
            }),
        ),
    ];
    for (verb, input) in admin_calls {
        let path = format!("/v1/core/facade/{verb}");
        let (status, body) = post_as_person_a(&fixture, &path, input).await;
        assert_refusal(
            status,
            &body,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            "a weave admin steps up on this credential first (MFA-1 A: an admin cannot skip it)",
            "the admin door refuses an unstepped caller",
        );
    }
    // W5: the admin doors refuse a malformed grant.
    let malformed_grant_calls = [
        (
            "vault.weave.admin.report",
            json!({"membership_grant": "zz"}),
        ),
        ("vault.weave.admin.lens", json!({"membership_grant": "zz"})),
        (
            "vault.weave.admin.digest",
            json!({"membership_grant": "zz"}),
        ),
        (
            "vault.weave.admin.link.wrong",
            json!({
                "membership_grant": "zz",
                "request": {
                    "source_ref": fresh_hex(),
                    "kind": "mentions",
                    "target_ref": fresh_hex(),
                },
            }),
        ),
        (
            "vault.weave.admin.item.wrong",
            json!({
                "membership_grant": "zz",
                "request": {"item": "claim", "item_ref": fresh_hex()},
            }),
        ),
    ];
    for (verb, input) in malformed_grant_calls {
        let path = format!("/v1/core/facade/{verb}");
        let (status, body) = post_as_owner(&fixture, &path, input).await;
        assert_refusal(
            status,
            &body,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "membership_grant is not a 32-hex membership grant id",
            "the admin door refuses a malformed grant",
        );
    }
    // W12: a bad change hex refuses in the verb input mapping.
    let (status, malformed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.setting_changes.answer",
        json!({"change_ref": "zz", "accept": true}),
    )
    .await;
    assert_refusal(
        status,
        &malformed,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "change_ref must be a 32-hex change id",
        "the verb input mapping refuses a bad change hex",
    );
    // W15: a bad link refuses in the wire link mapping.
    let (status, malformed) = post_as_person_a(
        &fixture,
        "/v1/core/facade/vault.weave.link.wrong",
        json!({
            "source_ref": "zz",
            "kind": "mentions",
            "target_ref": fresh_hex(),
        }),
    )
    .await;
    assert_refusal(
        status,
        &malformed,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "a weave link names entity ids",
        "the wire link mapping refuses non-hex refs",
    );
    let (status, malformed) = post_as_person_a(
        &fixture,
        "/v1/core/facade/vault.weave.link.wrong",
        json!({
            "source_ref": fresh_hex(),
            "kind": "nope",
            "target_ref": fresh_hex(),
        }),
    )
    .await;
    assert_refusal(
        status,
        &malformed,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "unknown weave edge kind",
        "the wire link mapping refuses an unknown edge kind",
    );
    // W17: a bad item refuses in the wire item mapping.
    let bad_items = [
        (
            json!({"item": "nope", "item_ref": fresh_hex()}),
            "a wrong weave item is a claim, project, budget, sieve audit or loop decision",
        ),
        (
            json!({"item": "budget", "item_ref": fresh_hex()}),
            "a weave budget item names its project_ref",
        ),
        (
            json!({
                "item": "claim",
                "item_ref": fresh_hex(),
                "project_ref": fresh_hex(),
            }),
            "only a weave budget item names a project_ref",
        ),
        (
            json!({"item": "claim", "item_ref": "zz"}),
            "a weave item names entity ids",
        ),
        (
            json!({"item": "loop_decision", "item_ref": "zz"}),
            "a weave loop item names a gate decision id",
        ),
    ];
    for (input, message) in bad_items {
        let (status, body) =
            post_as_person_a(&fixture, "/v1/core/facade/vault.weave.item.wrong", input).await;
        assert_refusal(
            status,
            &body,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            message,
            "the wire item mapping refuses a bad item",
        );
    }
    // W19: a person reading an owner-section recipe meets the role gate.
    let (status, refused) = post_as_person_a(
        &fixture,
        "/v1/core/facade/vault.weave.report",
        json!({"sections": [{"kind": "budgets"}]}),
    )
    .await;
    assert_refusal(
        status,
        &refused,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "invalid config: invalid weave report recipe",
        "the engine role gate refuses a person budgets recipe",
    );
    // W20: an unknown field refuses at the typed decode, before any proof.
    for verb in [
        "vault.weave.digest.render",
        "vault.weave.owner.digest.render",
        "vault.weave.schedules.list",
        "vault.weave.setting_changes.list",
    ] {
        let path = format!("/v1/core/facade/{verb}");
        let (status, body) = post_as_owner(&fixture, &path, json!({"nope": 1})).await;
        assert_eq!(
            (status, body["error"]["code"].as_str()),
            (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
            "{verb} refuses an unknown field: {body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("invalid SDK request: "),
            "{verb} names the decode failure: {body}"
        );
    }
    // W21: a bad reader ref refuses in the wire reader mapping.
    let (status, malformed) = post_as_owner(
        &fixture,
        "/v1/core/facade/vault.weave.schedules.clear",
        json!({"kind": "person", "reader_ref": "zz"}),
    )
    .await;
    assert_refusal(
        status,
        &malformed,
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "reader_ref is not an entity id",
        "the wire reader mapping refuses a bad reader ref",
    );
}
