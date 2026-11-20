//! No `self.desktop.*` verb has an HTTP facade door: a caller outside a run's
//! code mode cannot drive the desktop through `/v1/core/facade`.
//!
//! Each of the twenty desktop verbs, posted to `/v1/core/facade/<verb>` through
//! the in-process router with the owner's root slip and with a person's own
//! human slip, answers 404 `NOT_FOUND` "`<verb>` is not an SDK verb" from the
//! facade's unknown-verb fallback, which reads neither the actor nor the body.
//! No run is registered and no guest is configured. The code-mode half (a
//! credential that does not bind the verb, a read-only credential on a Write
//! row, a run with no desktop guest) needs a code host or a test door that
//! reaches `McpCodeModeVerbs`, so it is not in this file.
//!
//! Run: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features
//! oneiron/test-support,oneiron/test-hooks,oneiron-broker/test-support,tokio/test-util
//! --test self_desktop_doors`.
//!
//! Canon: no canon line states that desktop rows have no facade door. Code
//! mode is where the browser host verbs are called: "A mid planner tier writes
//! one batched code-mode program for each subgoal. The program calls the
//! browser host verbs" (`eiri/architecture/eiri-arch-0002-code-mode-execution.md:169`),
//! and the desktop rows take the same door to the run's own desktop guest
//! (`crates/oneiron-server/src/api/mcp_gateway/code_mode_verbs.rs`).
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

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

/// The twenty desktop verbs (`scripts/sdk/verbs/self.desktop.*.json`), none of
/// which has a facade door.
const VERBS: [&str; 20] = [
    "self.desktop.batch",
    "self.desktop.click",
    "self.desktop.click_at",
    "self.desktop.crop",
    "self.desktop.expect",
    "self.desktop.find",
    "self.desktop.handover",
    "self.desktop.hotkey",
    "self.desktop.key",
    "self.desktop.observe",
    "self.desktop.open",
    "self.desktop.screenshot",
    "self.desktop.scroll",
    "self.desktop.select",
    "self.desktop.type",
    "self.desktop.view",
    "self.desktop.wait_for",
    "self.desktop.window",
    "self.desktop.windows",
    "self.desktop.zoom",
];

/// A device vault, its app, and the owner's root slip.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
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

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("self-desktop-doors".into()),
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
    let app = build_app(server);
    Fixture {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
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

/// A live person's own human slip: the root's claims narrowed to that person,
/// the `human` class and the `read` and `write` verbs, bound to a fresh key.
fn person_credential(fixture: &Fixture) -> Credential {
    let person = EntityId::now();
    fixture
        .vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    let key = SigningKey::from_bytes(&[0x5B; 32]);
    let mut claims = fixture
        .vault
        .ensure_host_root_slip(&fixture.issuer)
        .expect("the host root slip")
        .claims;
    claims.slip_id = [0x5B; 32];
    claims.parent_id = None;
    claims.holder_ref = person.to_hex();
    claims.actor_class = Some("human".to_owned());
    claims.binding_key = key.verifying_key().to_bytes();
    claims.scope.verbs = ScopeAxis::Some(BTreeSet::from(["read".to_owned(), "write".to_owned()]));
    claims.records = BTreeSet::new();
    let slip = fixture
        .vault
        .mint_capability_slip(&fixture.issuer, claims)
        .expect("a credential");
    let token = slip.to_token().expect("a credential token");
    Credential { slip, key, token }
}

async fn post(fixture: &Fixture, verb: &str, token: &str, binding: String) -> (StatusCode, Value) {
    let request = Request::post(format!("/v1/core/facade/{verb}"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(json!({}).to_string()))
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

/// `verb` refused at the unknown-verb fallback: 404, `NOT_FOUND`, and the
/// fallback's own message naming the verb.
fn assert_not_a_facade_verb(status: StatusCode, answer: &Value, verb: &str, what: &str) {
    assert_eq!(status, StatusCode::NOT_FOUND, "{what}: {answer}");
    assert_eq!(
        answer["error"]["code"].as_str(),
        Some("NOT_FOUND"),
        "{what}: {answer}"
    );
    let expected_message = format!("`{verb}` is not an SDK verb");
    assert_eq!(
        answer["error"]["message"].as_str(),
        Some(expected_message.as_str()),
        "{what}: {answer}"
    );
}

/// No desktop verb has a facade door: the owner's root slip and a person's own
/// human slip each answer 404 `NOT_FOUND`, before the actor, the body or any
/// guest is touched.
#[test]
fn desktop_verbs_have_no_facade_door() {
    run_on_engine_stack("desktop-doors-no-facade", no_facade_cases);
}

async fn no_facade_cases() {
    let fixture = setup().await;
    let person = person_credential(&fixture);
    for verb in VERBS {
        let owner_proof = owner_binding(&fixture);
        let (status, answer) = post(&fixture, verb, &fixture.owner_token, owner_proof).await;
        assert_not_a_facade_verb(status, &answer, verb, &format!("the owner calls {verb}"));
        let person_binding =
            holder_proof(&person.slip, &person.key, fixture.vault.now_recorded_at())
                .expect("holder proof")
                .to_string();
        let (status, answer) = post(&fixture, verb, &person.token, person_binding).await;
        assert_not_a_facade_verb(status, &answer, verb, &format!("the person calls {verb}"));
    }
}
