//! A facet-narrowed OpenAI proxy key saves its exchange, not only answers
//! (FIX PROXY-REMEMBER-SUBJECT-UNREADABLE-UNDER-FACET-KEY; ARCH-0028 dr:F15,
//! "the loop is full, not read-only"; PROXY-EXCHANGE-SUBJECT = A).
//!
//! The exchange names the paired actor's own PERSON as its subject. A key
//! the owner narrowed to one facet does not read that PERSON (a PERSON is
//! never placed in a facet), so the OF-063 writer-read check refused
//! `/subject` and the reply said `Refused`. The subject now resolves for an
//! exchange recognised by its content and its writer's standing (an
//! `integration.exchange` tool output about the writer itself, while the
//! writer's proxy registration is live): the exchange lands Proposed, born
//! in the key's facet, and the same key's proposal about itself through
//! `POST /v1/core/propose` is still refused by that door's own subject read.
//!
//! Run: `cargo test --locked -p oneiron-server --all-features --test
//! openai_proxy_facet_key_remembers`.

#[path = "support/fake_llm.rs"]
mod fake_llm;

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
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId};
use oneiron::registry::{ENTITY_TYPE_FACET, ENTITY_TYPE_PERSON};
use oneiron::task_verb::sdk::{ChatCompletionRemembered, ChatCompletionResponse};
use oneiron::{ClaimSubject, EdgeActorClass, EntityId, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::config::models::ModelsConfig;
use oneiron_server::server::SyncServer;
use serde_json::{Value, json};
use tower::ServiceExt;

use fake_llm::{FakeLlm, Reply};

// The configured server secret that selects secret-based rooting at boot; it is
// config, not issuer key material. The test issuer is the keystore issuer the
// server bootstrapped, loaded back through `Vault::load_host_slip_issuer`.
const AUTH_SECRET: &str = "proxy-facet-key-remembers-auth-secret";
const QUERY: &str = "what did we decide about the harbor schedule";
const MODEL: &str = "local/test-model@live";
const EXCHANGE_PREDICATE: &str = "integration.exchange";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn holder_key(actor: &EntityId) -> SigningKey {
    SigningKey::from_bytes(&blake3::derive_key(
        "oneiron/test/proxy-rows-holder/v1",
        actor.to_hex().as_bytes(),
    ))
}

/// One stored FACET row, the only facet the narrowed key admits.
fn put_facet(vault: &Vault) -> EntityId {
    let facet = EntityId::now();
    vault
        .put_entity(
            &facet,
            ENTITY_TYPE_FACET,
            TimeRange { start: 1, end: 1 },
            1,
            b"proxy facet",
        )
        .expect("proxy facet row");
    facet
}

/// `Scope::top()` with its facets axis narrowed to `facet` alone: bands,
/// sensitivity, audience, worlds and verbs stay whole.
fn one_facet_scope(facet: EntityId) -> Scope {
    Scope {
        facets: ScopeAxis::Some(BTreeSet::from([ScopeId(facet)])),
        ..Scope::top()
    }
}

// The connector actor is a fresh human: the shipped default manifest's
// class-wide human ceiling covers any fresh actor, while its agent row is
// bound to one derived first-party id, so a fresh agent has no ceiling.
fn pair_connector(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    actor: EntityId,
    scope: Scope,
) -> (CapabilitySlip, SigningKey) {
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"proxy facet actor",
        )
        .expect("proxy facet actor row");
    let holder = actor.to_hex();
    let link = vault
        .issue_pairing_link_for_principal(
            issuer,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some(EdgeActorClass::Human.gate_actor_class().to_owned()),
                org_ref: None,
                write_facet: None,
                comm: None,
                seat: None,
            },
        )
        .expect("proxy facet pairing link");
    let key = holder_key(&actor);
    let binding = key.verifying_key().to_bytes();
    let transcript = pairing_binding_transcript(&link.code, &binding, &holder)
        .expect("proxy facet binding transcript");
    let signature = key.sign(&transcript);
    let slip = vault
        .redeem_pairing_link(issuer, &link.code, &holder, binding, &signature.to_bytes())
        .expect("proxy facet redeemed slip");
    (slip, key)
}

fn holder_auth(vault: &Vault, slip: &CapabilitySlip, key: &SigningKey) -> (String, String) {
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let transcript = slip
        .binding_transcript(challenge.as_bytes())
        .expect("proxy rows holder transcript");
    let signature = hex(&key.sign(&transcript).to_bytes());
    let bearer = slip.to_token().expect("proxy rows slip token");
    let binding =
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
    (format!("Bearer {bearer}"), binding)
}

fn owner_auth(vault: &Vault, issuer: &HostSlipIssuer) -> (String, String) {
    let slip = vault
        .ensure_host_root_slip(issuer)
        .expect("proxy rows host root slip");
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let proof = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .expect("proxy rows owner proof");
    let bearer = slip.to_token().expect("proxy rows owner token");
    let binding =
        json!({"timestamp": timestamp, "nonce": nonce, "signature": hex(&proof)}).to_string();
    (format!("Bearer {bearer}"), binding)
}

fn post(uri: &str, auth: &(String, String), body: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .header("authorization", auth.0.as_str())
        .header("x-oneiron-binding", auth.1.as_str())
        .body(Body::from(body.to_string()))
        .expect("proxy rows request")
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router.oneshot(request).await.expect("proxy rows response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("proxy rows body");
    let body: Value = serde_json::from_slice(&bytes).expect("proxy rows json body");
    (status, body)
}

async fn serve(vault: Arc<Vault>, base_url: &str) -> (Arc<SyncServer>, AiHost) {
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(AUTH_SECRET.to_owned()),
            ..Default::default()
        },
    )
    .expect("proxy rows server");
    let toml = format!(
        "default = \"local:test-model\"\n\
         extraction_egress = true\n\
         [providers.local]\n\
         kind = \"local-openai-compat\"\n\
         base_url = \"{base_url}\"\n"
    );
    let models = ModelsConfig::from_toml(&toml, None).expect("proxy rows models");
    let (server, host) = AiHost::attach(server, Some(&models)).await;
    (Arc::new(server), host)
}

async fn admit_proxy(router: &Router, vault: &Vault, issuer: &HostSlipIssuer, actor: EntityId) {
    let auth = owner_auth(vault, issuer);
    let request = post(
        "/v1/owner/connectors/proxy",
        &auth,
        json!({"actor": actor.to_hex()}),
    );
    let (status, body) = send(router.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "admit proxy: {body}");
}

async fn chat(
    router: &Router,
    vault: &Vault,
    slip: &CapabilitySlip,
    key: &SigningKey,
) -> ChatCompletionResponse {
    let auth = holder_auth(vault, slip, key);
    let request = post(
        "/v1/chat/completions",
        &auth,
        json!({"model": MODEL, "messages": [{"role": "user", "content": QUERY}]}),
    );
    let (status, body) = send(router.clone(), request).await;
    assert_eq!(status, StatusCode::OK, "chat completions: {body}");
    serde_json::from_value(body).expect("proxy rows chat response")
}

/// The proposed exchange's row id, from its `shortId:hash` reference.
fn exchange_id(vault: &Vault, short_ref: &str) -> EntityId {
    let (short_id, hash) = short_ref
        .split_once(':')
        .expect("exchange ref is shortId:hash");
    let hash = u8::from_str_radix(hash, 16).expect("exchange ref hash is two hex digits");
    let hydrated = vault
        .hydrate_short_id(short_id, hash)
        .expect("proxy rows exchange short id")
        .expect("proxy rows exchange short id resolves");
    assert!(hydrated.body.is_some(), "the exchange row is live");
    hydrated.id
}

/// A vault, its served router with a scripted model, the host issuer, and
/// one actor paired with a key narrowed to one facet and admitted as the
/// proxy's connector.
struct Paired {
    vault: Arc<Vault>,
    router: Router,
    host: AiHost,
    actor: EntityId,
    facet: EntityId,
    slip: CapabilitySlip,
    key: SigningKey,
    _fake: FakeLlm,
    _dir: tempfile::TempDir,
}

async fn paired_on_one_facet() -> Paired {
    let dir = tempfile::tempdir().expect("proxy facet dir");
    let mut config = VaultConfig::device();
    // The proxy recalls in call mode; a cold first recall in a debug build on
    // a loaded host can miss the default deadline. Not this test's subject.
    config.call_mode_deadline =
        std::time::Duration::from_millis(oneiron::memory::caps::MAX_RECALL_DEADLINE_MS);
    let vault = Arc::new(Vault::open(dir.path(), config).expect("proxy facet vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let fake = FakeLlm::start(Vec::new(), Some(Reply::text("the remembered answer"))).await;
    let (server, host) = serve(Arc::clone(&vault), &fake.base_url).await;
    let router = build_app(server);
    let issuer = vault
        .load_host_slip_issuer()
        .expect("proxy facet host issuer");
    let facet = put_facet(&vault);
    let actor = EntityId::now();
    let (slip, key) = pair_connector(&vault, &issuer, actor, one_facet_scope(facet));
    admit_proxy(&router, &vault, &issuer, actor).await;
    Paired {
        vault,
        router,
        host,
        actor,
        facet,
        slip,
        key,
        _fake: fake,
        _dir: dir,
    }
}

/// The proxy's recall, model call and proposal poll engine futures; the
/// router runs on threads sized as the server sizes its own
/// (`ENGINE_THREAD_STACK_BYTES`), on a multi-thread runtime as `build_app`
/// asks.
#[test]
fn a_facet_narrowed_proxy_key_saves_its_exchange() {
    run_on_engine_stack(
        "proxy-facet-key-saves",
        facet_narrowed_key_saves_its_exchange,
    );
}

async fn facet_narrowed_key_saves_its_exchange() {
    let paired = paired_on_one_facet().await;
    let answer = chat(&paired.router, &paired.vault, &paired.slip, &paired.key).await;
    // On main: Refused with code FORBIDDEN; the cause is the OF-063 denial
    // gate.deny.unresolved_record_reference at `/subject` (the key cannot
    // read its own PERSON), which the server log and the gate receipt name.
    let (claim, approval) = match answer.oneiron.remembered {
        ChatCompletionRemembered::Saved { claim, approval } => (claim, approval),
        refused => panic!("the facet-narrowed key's exchange was not saved: {refused:?}"),
    };
    assert_eq!(approval, "proposed", "the exchange lands Proposed");
    let exchange = exchange_id(&paired.vault, &claim);
    let stored = paired
        .vault
        .get_claim(&exchange)
        .expect("proxy facet exchange claim")
        .expect("proxy facet exchange stored");
    assert_eq!(stored.predicate, EXCHANGE_PREDICATE);
    assert!(
        matches!(stored.subject, ClaimSubject::Entity(subject) if subject == paired.actor),
        "the exchange names the paired actor: {:?}",
        stored.subject
    );
    assert_eq!(
        stored.scope_facet, paired.facet,
        "the exchange is born in the key's one facet"
    );
    paired.host.shutdown().await;
}

/// The exemption does not open the core door: the same key's proposal
/// about itself through `POST /v1/core/propose` is refused by that door's
/// own subject read (`subject_admitted`), before any claim write. Green on
/// main and on the fix.
#[test]
fn a_facet_narrowed_key_still_cannot_propose_about_itself_through_the_core_door() {
    run_on_engine_stack(
        "proxy-facet-key-core-door",
        facet_narrowed_key_core_door_refused,
    );
}

async fn facet_narrowed_key_core_door_refused() {
    let paired = paired_on_one_facet().await;
    let auth = holder_auth(&paired.vault, &paired.slip, &paired.key);
    let request = post(
        "/v1/core/propose",
        &auth,
        json!({
            "subject": paired.actor.to_hex(),
            "predicate": EXCHANGE_PREDICATE,
            "value": {"user": QUERY, "assistant": "an answer", "model": MODEL},
        }),
    );
    let (status, body) = send(paired.router.clone(), request).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "the key's own-subject proposal on the core door is refused: {body}"
    );
    assert!(
        body.to_string()
            .contains("subject not found or not readable"),
        "the core door's own subject read refuses it: {body}"
    );
    paired.host.shutdown().await;
}
