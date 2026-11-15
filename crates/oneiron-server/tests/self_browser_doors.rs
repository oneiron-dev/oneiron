//! An agent drives a browser only through its own attached live run, and each
//! browser door refuses everyone else before any guest is touched.
//!
//! HTTP `POST /v1/core/facade/<verb>` through the in-process router, over the
//! four host doors `self.browser.open`, `self.browser.type`,
//! `self.browser.expect` and `self.browser.handover`. No run is registered
//! and no guest is configured, so every call below is refused at admission;
//! each test proves the refusal comes from the right layer, with the source's
//! own status, error code and message. The four verbs share one door body
//! (`on_browser`) and one guard (`hold_live_run`), so every row runs against
//! all four verbs, except the read-only row, which runs only against the
//! three Write verbs.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test self_browser_doors`.
//!
//! Canon: no canon line states the attached-live-run rule this file proves
//! (REPORT.md records "no canon line found"). The nearest browser line is the
//! browser box: "The cookies stay in that box and never enter the runner."
//! (`canon/oneiron/gate/oneiron-arch-0069-secret-custody-v1.md:156`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use ed25519_dalek::SigningKey;
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, holder_proof};
use oneiron::federation::ScopeAxis;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The four browser host doors this file proves.
const VERBS: [&str; 4] = [
    "self.browser.open",
    "self.browser.type",
    "self.browser.expect",
    "self.browser.handover",
];

/// The three doors whose row scope is Write.
const WRITE_VERBS: [&str; 3] = [
    "self.browser.open",
    "self.browser.type",
    "self.browser.handover",
];

/// A handle with none of the guard's `lr1.<run>.<issued>` syntax.
const MALFORMED_HANDLE: &str = "not-a-live-run-handle";

/// A well-formed handle that names no registered run and no attachment.
const UNKNOWN_HANDLE: &str =
    "lr1.11111111111111111111111111111111.22222222222222222222222222222222";

/// A session header that is no 32-hex id.
const BAD_SESSION: &str = "not-a-session";

/// The record bound that narrows the record-narrowed slip.
const NARROW_RECORD: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// `LiveRunRefusal::Invalid`'s fixed text.
const INVALID_MESSAGE: &str = "the live-run handle is malformed";
/// `LiveRunRefusal::Unavailable`'s fixed text.
const UNAVAILABLE_MESSAGE: &str = "no live run this credential may act for";
/// `facade_actor`'s refusal for a slip that names no principal.
const PRINCIPAL_MESSAGE: &str = "facade routes bind writes to an authenticated principal";
/// `facade_actor`'s refusal for a slip that names no actor class.
const CLASS_MESSAGE: &str = "facade routes bind writes to a declared actor class";
/// `ApiError::forbidden_scope`'s fixed text, for scope and record scope alike.
const SCOPE_MESSAGE: &str = "request does not have the required scope";
/// `hold_live_run`'s refusal for any call made inside a session.
const OFF_RECORD_MESSAGE: &str =
    "live child admission requires the attached run's canonical storage";
/// `FacadeCall::session`'s refusal for a malformed session header.
const SESSION_MESSAGE: &str = "invalid session header";
/// `validate_input`'s decode refusal, before the path it names.
const DECODE_PREFIX: &str = "invalid SDK request: ";

/// A device vault, its server and app, and the owner, person and agent ids.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    person: EntityId,
    agent: EntityId,
}

/// One minted slip with its holder key and presented token.
struct Credential {
    slip: CapabilitySlip,
    key: SigningKey,
    token: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A distinct slip id for each credential a test mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

/// The key one credential binds; its holder proves it per request.
fn holder_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn person(vault: &Vault, id: EntityId) {
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("self-browser-doors".into()),
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
    let person_id = EntityId::now();
    person(&vault, person_id);
    let agent_id = vault
        .ensure_agent_principal("browser-doors-agent")
        .expect("agent principal");
    let app = build_app(server);
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        person: person_id,
        agent: agent_id,
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

fn slip_binding(fixture: &Fixture, slip: &CapabilitySlip, key: &SigningKey) -> String {
    holder_proof(slip, key, fixture.vault.now_recorded_at())
        .expect("holder proof")
        .to_string()
}

/// A credential this host mints: the root's claims narrowed to `holder`,
/// `actor`, `verbs` and `records`, proved by the key `seed` names.
fn mint_credential(
    fixture: &Fixture,
    holder: &str,
    actor: Option<&str>,
    verbs: BTreeSet<String>,
    records: BTreeSet<String>,
    seed: u8,
) -> Credential {
    let key = holder_key(seed);
    let mut claims = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_owned();
    claims.actor_class = actor.map(str::to_owned);
    claims.binding_key = key.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(verbs);
    claims.records = records;
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("a credential");
    let token = slip.to_token().expect("a credential token");
    Credential { slip, key, token }
}

fn read_write_verbs() -> BTreeSet<String> {
    BTreeSet::from(["read".to_owned(), "write".to_owned()])
}

fn read_only_verbs() -> BTreeSet<String> {
    BTreeSet::from(["read".to_owned()])
}

/// The valid `spec` for `verb`: the shape its input requires.
fn valid_spec(verb: &str) -> Value {
    match verb {
        "self.browser.open" => json!({"url": "https://example.com/"}),
        "self.browser.type" => json!({"ref": "r1", "text": "hello"}),
        "self.browser.expect" => json!({}),
        "self.browser.handover" => json!({"reason": "sign in to continue"}),
        _ => unreachable!("the table holds the four browser verbs only"),
    }
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
    let answer: Value = serde_json::from_slice(&bytes).expect("facade response JSON");
    (status, answer)
}

async fn post_with_session(
    fixture: &Fixture,
    path: &str,
    token: &str,
    binding: String,
    body: Value,
    session: &str,
) -> (StatusCode, Value) {
    let request = Request::post(path)
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("x-oneiron-session", session)
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

async fn post_as_owner(fixture: &Fixture, verb: &str, body: Value) -> (StatusCode, Value) {
    let binding = owner_binding(fixture);
    let path = format!("/v1/core/facade/{verb}");
    let token = fixture.owner_token.clone();
    post(fixture, &path, &token, binding, body).await
}

async fn post_as_credential(
    fixture: &Fixture,
    verb: &str,
    body: Value,
    credential: &Credential,
) -> (StatusCode, Value) {
    let binding = slip_binding(fixture, &credential.slip, &credential.key);
    let path = format!("/v1/core/facade/{verb}");
    post(fixture, &path, &credential.token, binding, body).await
}

async fn post_owner_session(
    fixture: &Fixture,
    verb: &str,
    body: Value,
    session: &str,
) -> (StatusCode, Value) {
    let binding = owner_binding(fixture);
    let path = format!("/v1/core/facade/{verb}");
    let token = fixture.owner_token.clone();
    post_with_session(fixture, &path, &token, binding, body, session).await
}

fn assert_refusal(
    status: StatusCode,
    answer: &Value,
    expected_status: StatusCode,
    expected_code: &str,
    expected_message: &str,
    what: &str,
) {
    assert_eq!(status, expected_status, "{what}: {answer}");
    assert_eq!(
        answer["error"]["code"].as_str(),
        Some(expected_code),
        "{what}: {answer}"
    );
    assert_eq!(
        answer["error"]["message"].as_str(),
        Some(expected_message),
        "{what}: {answer}"
    );
}

fn assert_decode_refusal(status: StatusCode, answer: &Value, field: &str, what: &str) {
    assert_eq!(status, StatusCode::BAD_REQUEST, "{what}: {answer}");
    assert_eq!(
        answer["error"]["code"].as_str(),
        Some("BAD_REQUEST"),
        "{what}: {answer}"
    );
    let message = answer["error"]["message"]
        .as_str()
        .expect("a decode refusal names its shape");
    assert!(message.starts_with(DECODE_PREFIX), "{what}: {answer}");
    assert!(message.contains(field), "{what}: {answer}");
}

/// The owner's root slip, a person's own human slip and an agent's own slip
/// each reach the live-run guard: a malformed handle is 400
/// `live_run_invalid`, a well-formed unknown one 403 `live_run_unavailable`.
#[test]
fn browser_doors_need_the_callers_own_live_run() {
    run_on_engine_stack("browser-doors-live-run", live_run_cases);
}

async fn live_run_cases() {
    let fixture = setup().await;
    let person_hex = fixture.person.to_hex();
    let agent_hex = fixture.agent.to_hex();
    let person_credential = mint_credential(
        &fixture,
        &person_hex,
        Some("human"),
        read_write_verbs(),
        BTreeSet::new(),
        0x5B,
    );
    let agent_credential = mint_credential(
        &fixture,
        &agent_hex,
        Some("agent"),
        read_write_verbs(),
        BTreeSet::new(),
        0xA6,
    );
    for verb in VERBS {
        for (handle, expected_status, expected_code, expected_message) in [
            (
                MALFORMED_HANDLE,
                StatusCode::BAD_REQUEST,
                "live_run_invalid",
                INVALID_MESSAGE,
            ),
            (
                UNKNOWN_HANDLE,
                StatusCode::FORBIDDEN,
                "live_run_unavailable",
                UNAVAILABLE_MESSAGE,
            ),
        ] {
            let body = json!({"live_run": handle, "spec": valid_spec(verb)});
            let owner_what = format!("the owner calls {verb} with {handle}");
            let (status, answer) = post_as_owner(&fixture, verb, body.clone()).await;
            assert_refusal(
                status,
                &answer,
                expected_status,
                expected_code,
                expected_message,
                &owner_what,
            );
            let person_what = format!("the person calls {verb} with {handle}");
            let (status, answer) =
                post_as_credential(&fixture, verb, body.clone(), &person_credential).await;
            assert_refusal(
                status,
                &answer,
                expected_status,
                expected_code,
                expected_message,
                &person_what,
            );
            let agent_what = format!("the agent calls {verb} with {handle}");
            let (status, answer) =
                post_as_credential(&fixture, verb, body, &agent_credential).await;
            assert_refusal(
                status,
                &answer,
                expected_status,
                expected_code,
                expected_message,
                &agent_what,
            );
        }
    }
}

/// A slip with no principal, one with no actor class, a read-only slip on a
/// Write verb, and a record-narrowed slip are each refused 403 `FORBIDDEN`
/// before the live-run guard: each carries a well-formed unknown handle, so
/// a wrong layer would answer `live_run_unavailable` instead.
#[test]
fn browser_doors_refuse_unbound_and_narrowed_credentials() {
    run_on_engine_stack("browser-doors-unbound", unbound_cases);
}

async fn unbound_cases() {
    let fixture = setup().await;
    let person_hex = fixture.person.to_hex();
    let without_principal = mint_credential(
        &fixture,
        "host",
        None,
        read_write_verbs(),
        BTreeSet::new(),
        0x1D,
    );
    let without_class = mint_credential(
        &fixture,
        &person_hex,
        None,
        read_write_verbs(),
        BTreeSet::new(),
        0x5B,
    );
    let read_only = mint_credential(
        &fixture,
        &person_hex,
        Some("human"),
        read_only_verbs(),
        BTreeSet::new(),
        0x5C,
    );
    let narrowed = mint_credential(
        &fixture,
        &person_hex,
        Some("human"),
        read_write_verbs(),
        BTreeSet::from([NARROW_RECORD.to_owned()]),
        0x5D,
    );
    for verb in VERBS {
        let body = json!({"live_run": UNKNOWN_HANDLE, "spec": valid_spec(verb)});
        let principal_what = format!("{verb} for a slip with no principal");
        let (status, answer) =
            post_as_credential(&fixture, verb, body.clone(), &without_principal).await;
        assert_refusal(
            status,
            &answer,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            PRINCIPAL_MESSAGE,
            &principal_what,
        );
        let class_what = format!("{verb} for a slip with no actor class");
        let (status, answer) =
            post_as_credential(&fixture, verb, body.clone(), &without_class).await;
        assert_refusal(
            status,
            &answer,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            CLASS_MESSAGE,
            &class_what,
        );
        let narrowed_what = format!("{verb} for a record-narrowed slip");
        let (status, answer) = post_as_credential(&fixture, verb, body, &narrowed).await;
        assert_refusal(
            status,
            &answer,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            SCOPE_MESSAGE,
            &narrowed_what,
        );
    }
    for verb in WRITE_VERBS {
        let body = json!({"live_run": UNKNOWN_HANDLE, "spec": valid_spec(verb)});
        let scope_what = format!("{verb} for a read-only slip");
        let (status, answer) = post_as_credential(&fixture, verb, body, &read_only).await;
        assert_refusal(
            status,
            &answer,
            StatusCode::FORBIDDEN,
            "FORBIDDEN",
            SCOPE_MESSAGE,
            &scope_what,
        );
    }
}

/// Any well-formed session header turns the call off-record: 409
/// `OFF_RECORD_SESSION_DOOR`. A malformed one is 400 `BAD_REQUEST`.
#[test]
fn browser_doors_refuse_an_off_record_session() {
    run_on_engine_stack("browser-doors-session", session_cases);
}

async fn session_cases() {
    let fixture = setup().await;
    let session = EntityId::now().to_hex();
    for verb in VERBS {
        let body = json!({"live_run": UNKNOWN_HANDLE, "spec": valid_spec(verb)});
        let seated_what = format!("{verb} inside a session");
        let (status, answer) = post_owner_session(&fixture, verb, body.clone(), &session).await;
        assert_refusal(
            status,
            &answer,
            StatusCode::CONFLICT,
            "OFF_RECORD_SESSION_DOOR",
            OFF_RECORD_MESSAGE,
            &seated_what,
        );
        let ragged_what = format!("{verb} with a malformed session");
        let (status, answer) = post_owner_session(&fixture, verb, body, BAD_SESSION).await;
        assert_refusal(
            status,
            &answer,
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            SESSION_MESSAGE,
            &ragged_what,
        );
    }
}

/// The body decodes before the guard runs: without `live_run`, and with a
/// well-formed handle beside a mistyped `spec`, the answer is 400
/// `BAD_REQUEST`, never a live-run code.
#[test]
fn browser_doors_decode_the_body_before_the_guard() {
    run_on_engine_stack("browser-doors-decode", decode_cases);
}

async fn decode_cases() {
    let fixture = setup().await;
    for verb in VERBS {
        let missing = json!({"spec": valid_spec(verb)});
        let missing_what = format!("{verb} without its live run");
        let (status, answer) = post_as_owner(&fixture, verb, missing).await;
        assert_decode_refusal(status, &answer, "live_run", &missing_what);
        let mistyped = json!({"live_run": UNKNOWN_HANDLE, "spec": 42});
        let mistyped_what = format!("{verb} with a mistyped spec");
        let (status, answer) = post_as_owner(&fixture, verb, mistyped).await;
        assert_decode_refusal(status, &answer, "spec", &mistyped_what);
    }
}
