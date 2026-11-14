//! The owner's answer to a quota question is an owner act (FIX-LIST
//! OWNER-GRADE-IS-NOT-OWNERSHIP; the lead's ruling 15 Nov 02:2x).
//!
//! `POST /v1/ai/quota/{question}` with `use_fallback` names the model a
//! parked offer's calls go to while it is parked: the owner's standing model
//! fallback (`MODEL_OWNER_FALLBACK`). A full-vault slip is a scope, not a
//! Grant naming this act, and its grade says nothing of whose it is. A live,
//! unattenuated, reusable full-vault slip the host minted to a person who
//! does not own the vault, or to an agent, is refused 403: the fallback stays
//! unset and the question stays open. The owner's own slips pass, because
//! their subject is the owner: his full slip on one of his devices, and the
//! host's root slip his CLI acts on (204, the fallback set, the question
//! closed).
//!
//! On main the route checks only the credential's grade, so the non-owner's
//! answer is taken (204) and the fallback is set: the first test is red
//! there and green with the owner door. The owner cases pass on both.
//!
//! Deterministic: one in-process vault, server and router per case
//! (`oneshot`, no ports, no model configured, no model called). The quota
//! question is the row the runtime keeps when an offer parks, written as
//! fixture state.
//!
//! Fleet command: `cargo test --locked -p oneiron-server --all-features
//! --test quota_answer_requires_vault_owner`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::llm::SpentKind;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::models::{QuotaChoice, QuotaFallback, QuotaQuestion};
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::json;
use tower::ServiceExt;

/// The parked offer's question id: the offer's key (hex64), as the runtime
/// names it.
const QUESTION: &str = "faaf460e714b9cd903038e250f3987e9c0e0576d2c13c8c75e7c5488f54fbdd4";
/// Where the runtime keeps an open quota question (`QUESTION_PREFIX` in
/// `models/cooldown.rs`).
const QUESTION_KEY_PREFIX: &str = "models:offer-cooldown:v1:ask:";
/// The model on another provider the question offers as the fallback.
const FALLBACK_MODEL: &str = "cloud/big@1";

/// A distinct slip id for each credential a case mints.
fn next_slip_id() -> [u8; 32] {
    static NEXT: AtomicU8 = AtomicU8::new(1);
    [NEXT.fetch_add(1, Ordering::Relaxed); 32]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One self-hosted vault with its embedded owner, its served router, and
/// one open quota question that offers `use_fallback` to [`FALLBACK_MODEL`].
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    _host: AiHost,
    app: Router,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    owner: EntityId,
}

async fn setup() -> Fixture {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    // The keystore goes in before the server: construction roots the vault.
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = SyncServer::new(
        Arc::clone(&vault),
        SyncServerConfig {
            auth_secret: Some("quota-answer-requires-vault-owner".into()),
            ..Default::default()
        },
    )
    .expect("create server");
    let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("the host root slip");
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("this install's live machine profile");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    // No model is configured; the host still keeps its rests, and so its
    // quota questions, in this vault.
    let (server, host) = AiHost::attach(server, None).await;
    let app = build_app(Arc::new(server));
    open_question(&vault);
    Fixture {
        _dir: dir,
        vault,
        _host: host,
        app,
        issuer,
        root,
        owner,
    }
}

fn question_key() -> String {
    format!("{QUESTION_KEY_PREFIX}{QUESTION}")
}

/// The question the runtime keeps when the offer parks on a spent window:
/// wait, or use the usage left on another provider's model.
fn open_question(vault: &Vault) {
    let question = QuotaQuestion {
        id: QUESTION.to_owned(),
        asked_at: vault.now_recorded_at(),
        provider: "own".to_owned(),
        model: "own/small@1".to_owned(),
        route: "chat".to_owned(),
        spent: SpentKind::Window,
        resets_at: None,
        choices: vec![QuotaChoice::Wait, QuotaChoice::UseFallback],
        fallbacks: vec![QuotaFallback {
            provider: "cloud".to_owned(),
            model: FALLBACK_MODEL.to_owned(),
        }],
        account: None,
    };
    let bytes = rmp_serde::to_vec_named(&question).expect("encode the quota question");
    vault
        .sync_state_put(&question_key(), &bytes)
        .expect("keep the open quota question");
    assert!(question_open(vault), "the fixture's question is open");
    assert_eq!(
        fallback(vault),
        None,
        "the fixture names no owner fallback for the offer"
    );
}

fn question_open(vault: &Vault) -> bool {
    vault
        .sync_state_get(&question_key())
        .expect("read the quota question")
        .is_some()
}

fn fallback(vault: &Vault) -> Option<String> {
    vault
        .model_fallback(QUESTION)
        .expect("read the owner's model fallback")
}

/// A live person of this vault who is not its owner.
fn non_owner_person(vault: &Vault) -> EntityId {
    let person = EntityId::now();
    vault
        .put_entity(
            &person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"human",
        )
        .expect("a live person");
    person
}

/// A live, logged, reusable full-vault slip the host mints `holder` at
/// `class`, bound to `key`: the root's own top scope and no caveat, so it is
/// owner grade whoever holds it.
fn full_slip(fx: &Fixture, holder: EntityId, class: &str, key: &SigningKey) -> CapabilitySlip {
    let mut claims = fx.root.claims.clone();
    claims.slip_id = next_slip_id();
    claims.parent_id = None;
    claims.holder_ref = holder.to_hex();
    claims.actor_class = Some(class.to_owned());
    claims.binding_key = key.verifying_key().to_bytes();
    fx.vault
        .mint_capability_slip(&fx.issuer, claims)
        .expect("a live full-vault slip")
}

/// One request's `x-oneiron-binding` header: a fresh challenge, signed by
/// `sign` (the holder's proof of possession).
fn binding_header(fx: &Fixture, sign: impl FnOnce(&[u8]) -> Vec<u8>) -> String {
    let timestamp = fx.vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let signature = hex(&sign(challenge.as_bytes()));
    json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
}

/// The holder's proof of possession of `slip` with `key`.
fn holder_binding(fx: &Fixture, slip: &CapabilitySlip, key: &SigningKey) -> String {
    binding_header(fx, |challenge| {
        let transcript = slip
            .binding_transcript(challenge)
            .expect("binding transcript");
        key.sign(&transcript).to_bytes().to_vec()
    })
}

/// The host's proof of possession of its root slip.
fn root_binding(fx: &Fixture) -> String {
    binding_header(fx, |challenge| {
        fx.issuer
            .binding_proof(&fx.root, challenge)
            .expect("root holder proof")
    })
}

/// Answers the question `use_fallback` to [`FALLBACK_MODEL`] over the real
/// route with `slip`, proved by `binding`.
async fn answer_use_fallback(
    fx: &Fixture,
    slip: &CapabilitySlip,
    binding: String,
) -> (StatusCode, String) {
    let token = slip.to_token().expect("slip token");
    let request = Request::post(format!("/v1/ai/quota/{QUESTION}"))
        .header("authorization", format!("Bearer {token}"))
        .header("x-oneiron-binding", binding)
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"choice": "use_fallback", "fallback": FALLBACK_MODEL}).to_string(),
        ))
        .expect("quota answer request");
    let response = fx
        .app
        .clone()
        .oneshot(request)
        .await
        .expect("quota answer response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("quota answer body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// H1: a person who does not own the vault, and an agent, each holding a
/// live full-vault slip with no Grant naming this act, cannot set the
/// owner's model fallback. Red on main (204, the fallback set).
#[test]
fn non_owner_full_scope_slip_cannot_select_owner_model_fallback() {
    run_on_engine_stack("quota-answer-non-owner", || async {
        for class in ["human", "agent"] {
            let fx = setup().await;
            let holder = if class == "human" {
                non_owner_person(&fx.vault)
            } else {
                fx.vault
                    .ensure_agent_principal("quota-answer-agent")
                    .expect("a registered agent principal")
            };
            assert_ne!(holder, fx.owner, "the {class} holder is not the owner");
            let key = SigningKey::from_bytes(&[0x51; 32]);
            let slip = full_slip(&fx, holder, class, &key);
            let binding = holder_binding(&fx, &slip, &key);
            let (status, body) = answer_use_fallback(&fx, &slip, binding).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "a non-owner {class}'s full-vault slip answers the owner's quota question: {body}"
            );
            assert_eq!(
                fallback(&fx.vault),
                None,
                "a non-owner {class} set the owner's model fallback"
            );
            assert!(
                question_open(&fx.vault),
                "a non-owner {class} closed the owner's quota question"
            );
        }
    });
}

/// The ruling's green case: the owner's own full slip, on one of his
/// devices, still sets his fallback. He is not locked out.
#[test]
fn owner_device_full_slip_selects_owner_model_fallback() {
    run_on_engine_stack("quota-answer-owner-device", || async {
        let fx = setup().await;
        let key = SigningKey::from_bytes(&[0x6D; 32]);
        let slip = full_slip(&fx, fx.owner, "human", &key);
        let binding = holder_binding(&fx, &slip, &key);
        let (status, body) = answer_use_fallback(&fx, &slip, binding).await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "the owner's own full slip answers his quota question: {body}"
        );
        assert_eq!(fallback(&fx.vault).as_deref(), Some(FALLBACK_MODEL));
        assert!(
            !question_open(&fx.vault),
            "the owner's answer closes the question"
        );
    });
}

/// The owner's CLI acts on the self-hosted root slip, as the owner the host
/// action names: it still sets his fallback.
#[test]
fn owner_host_root_slip_selects_owner_model_fallback() {
    run_on_engine_stack("quota-answer-owner-root", || async {
        let fx = setup().await;
        let binding = root_binding(&fx);
        let (status, body) = answer_use_fallback(&fx, &fx.root, binding).await;
        assert_eq!(
            status,
            StatusCode::NO_CONTENT,
            "the self-hosted root answers the owner's quota question: {body}"
        );
        assert_eq!(fallback(&fx.vault).as_deref(), Some(FALLBACK_MODEL));
        assert!(
            !question_open(&fx.vault),
            "the owner's answer closes the question"
        );
    });
}
