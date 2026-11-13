//! The OpenAI proxy's exchange claim names the recalled row its prompt carried.
//!
//! One seeded claim carries a distinctive word the caller's query lacks. The
//! test calls `POST /v1/chat/completions` through the HTTP door with a scripted
//! local model, asserts the injected memory block (and only it) carried the
//! word, then resolves the response's saved claim ref through the public
//! `Vault::hydrate_short_id` library door to the exact proposed row and asserts
//! its birth, read through `Vault::row_birth`, names the seeded row as a prompt
//! input. The exchange lands Proposed, and `POST /v1/core/hydrate` reads the
//! surfaceable lane (auto and approved claims only), so that door does not
//! serve it.

#[path = "support/fake_llm.rs"]
mod fake_llm;

#[path = "support/engine_stack.rs"]
mod engine_stack;

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
use oneiron::federation::Scope;
use oneiron::provenance::made_by::MadeByInputRole;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::sdk::{ChatCompletionRemembered, ChatCompletionResponse};
use oneiron::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSubject, EdgeActorClass, EntityId,
    TimeRange, Vault, VaultConfig,
};
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
const AUTH_SECRET: &str = "proxy-recall-names-rows-auth-secret";
const WORD: &str = "zorblax";
const QUERY: &str = "harbor lighthouse brass night crossings";
const MODEL: &str = "local/test-model@live";
const SEED_PREDICATE: &str = "test.proxy_seed";
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

// The connector actor is a fresh human: the shipped default manifest's
// class-wide human ceiling covers any fresh actor, while its agent row is
// bound to one derived first-party id, so a fresh agent has no ceiling.
fn pair_connector(
    vault: &Vault,
    issuer: &HostSlipIssuer,
    actor: EntityId,
) -> (CapabilitySlip, SigningKey) {
    vault
        .put_entity(
            &actor,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"proxy rows actor",
        )
        .expect("proxy rows actor row");
    let holder = actor.to_hex();
    let link = vault
        .issue_pairing_link_for_principal(
            issuer,
            Scope::top(),
            3600,
            PairingPrincipal {
                holder_ref: Some(holder.clone()),
                actor_class: Some(EdgeActorClass::Human.gate_actor_class().to_owned()),
                org_ref: None,
                write_facet: None,
                comm: None,
            },
        )
        .expect("proxy rows pairing link");
    let key = holder_key(&actor);
    let binding = key.verifying_key().to_bytes();
    let transcript = pairing_binding_transcript(&link.code, &binding, &holder)
        .expect("proxy rows binding transcript");
    let signature = key.sign(&transcript);
    let slip = vault
        .redeem_pairing_link(issuer, &link.code, &holder, binding, &signature.to_bytes())
        .expect("proxy rows redeemed slip");
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

fn message_text(message: &Value) -> String {
    let content = &message["content"];
    if let Some(text) = content.as_str() {
        return text.to_owned();
    }
    content.as_array().map_or_else(String::new, |parts| {
        parts
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n")
    })
}

fn message_texts(body: &Value) -> Vec<String> {
    body["messages"]
        .as_array()
        .map_or_else(Vec::new, |messages| {
            messages.iter().map(message_text).collect()
        })
}

fn seed_word_claim(vault: &Vault) -> EntityId {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"proxy rows subject",
        )
        .expect("proxy rows subject row");
    let text = format!("the harbor lighthouse keeps a brass {WORD} for night crossings");
    let body = ClaimBody::new(
        SEED_PREDICATE,
        ClaimSubject::Entity(subject),
        rmpv::Value::from(text.as_str()),
        0.8,
        ClaimApprovalStatus::Auto,
        ClaimLifecycleStatus::Active,
    )
    .expect("proxy rows claim body");
    let id = EntityId::now();
    vault
        .put_claim(
            &id,
            &body,
            TimeRange {
                start: 100,
                end: 100,
            },
            101,
        )
        .expect("proxy rows seed claim");
    vault
        .batch()
        .text(&id, &[("body", text.as_str())])
        .commit()
        .expect("proxy rows text index");
    vault
        .set_indexed_idle_delay_ms(0)
        .expect("proxy rows index delay");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("proxy rows index refresh");
    assert!(
        published.failed.is_empty(),
        "proxy rows index publish failed: {:?}",
        published.failed
    );
    id
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

/// The proxy's recall, model call and proposal poll engine futures; the
/// router runs on threads sized as the server sizes its own
/// (`ENGINE_THREAD_STACK_BYTES`), on a multi-thread runtime as `build_app`
/// asks.
#[test]
fn exchange_claim_birth_names_the_recalled_row() {
    run_on_engine_stack("proxy-recall-names-rows", exchange_birth_names_recalled_row);
}

async fn exchange_birth_names_recalled_row() {
    assert!(
        !QUERY.contains(WORD),
        "the query must not carry the seeded word"
    );
    let dir = tempfile::tempdir().expect("proxy rows dir");
    let mut config = VaultConfig::device();
    // The proxy recalls in call mode, which answers an empty partial pack once
    // the vault's call-mode deadline (100 ms by default) has passed; a cold
    // first recall in a debug test build on a loaded host misses it. This test
    // is not about the deadline, so it gets the longest one, as the voice host
    // tests do.
    config.call_mode_deadline =
        std::time::Duration::from_millis(oneiron::memory::caps::MAX_RECALL_DEADLINE_MS);
    let vault = Arc::new(Vault::open(dir.path(), config).expect("proxy rows vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let fake = FakeLlm::start(Vec::new(), Some(Reply::text("the remembered answer"))).await;
    let (server, host) = serve(Arc::clone(&vault), &fake.base_url).await;
    let router = build_app(server);
    let issuer = vault
        .load_host_slip_issuer()
        .expect("proxy rows host issuer");
    let actor = EntityId::now();
    let (slip, key) = pair_connector(&vault, &issuer, actor);
    let seeded = seed_word_claim(&vault);
    admit_proxy(&router, &vault, &issuer, actor).await;
    let answer = chat(&router, &vault, &slip, &key).await;
    assert!(
        answer.oneiron.recall_skipped.is_none(),
        "the connector's recall setting withheld recall: {:?}",
        answer.oneiron.recall_skipped
    );
    assert!(answer.oneiron.injected, "recall found nothing to inject");
    let claim = match answer.oneiron.remembered {
        ChatCompletionRemembered::Saved { claim, .. } => claim,
        refused => panic!("the exchange was not proposed: {refused:?}"),
    };
    let mut calls = fake
        .seen()
        .into_iter()
        .filter(|request| {
            message_texts(&request.body)
                .iter()
                .any(|text| text == QUERY)
        })
        .map(|request| message_texts(&request.body));
    let texts = calls.next().expect("the model saw the query call");
    assert!(
        calls.next().is_none(),
        "the model saw one call for the query"
    );
    let carriers: Vec<&String> = texts.iter().filter(|text| text.contains(WORD)).collect();
    assert_eq!(
        carriers.len(),
        1,
        "only the injected memory block carries the seeded word: {texts:?}"
    );
    assert_ne!(
        carriers[0].as_str(),
        QUERY,
        "the carrier is memory, not the query"
    );
    let exchange = exchange_id(&vault, &claim);
    let stored = vault
        .get_claim(&exchange)
        .expect("proxy rows exchange claim")
        .expect("proxy rows exchange stored");
    assert_eq!(
        stored.predicate, EXCHANGE_PREDICATE,
        "the hydrated row is the proposed exchange"
    );
    let prompt_rows: Vec<EntityId> = vault
        .row_birth(&exchange)
        .expect("proxy rows exchange birth")
        .into_iter()
        .flat_map(|birth| birth.made_by.inputs)
        .filter(|input| input.role == MadeByInputRole::Prompt)
        .map(|input| input.row)
        .collect();
    assert!(
        prompt_rows.contains(&seeded),
        "the birth names the recalled row: {prompt_rows:?}"
    );
    host.shutdown().await;
}
