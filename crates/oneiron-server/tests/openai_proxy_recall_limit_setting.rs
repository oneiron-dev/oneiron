//! The OpenAI proxy recalls at most the owner's `proxy.openai.recall_limit`
//! memory rows into one turn's injected memory block.
//!
//! Twelve seeded claims all match the turn's query, each carrying a marker
//! word of its own. The test calls `POST /v1/chat/completions` through the
//! HTTP door with a scripted local model, then counts how many markers the
//! injected memory block carried: with the key at 12, all twelve; at the
//! default of 8, eight.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test openai_proxy_recall_limit_setting`
//! (the cfg exports `oneiron_keystore::MemoryKeystore`).

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
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::Scope;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::setting::{SetSetting, SettingCaller, SettingMode, SettingScope};
use oneiron::store::GateDecisionId;
use oneiron::task_verb::sdk::ChatCompletionResponse;
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
const AUTH_SECRET: &str = "proxy-recall-limit-auth-secret";
const QUERY: &str = "harbor lighthouse brass night crossings";
const MODEL: &str = "local/test-model@live";
const SEED_PREDICATE: &str = "test.proxy_seed";
const RECALL_KEY: &str = "proxy.openai.recall_limit";

/// One marker word per seeded claim: counting the markers the injected
/// block carries counts the rows the turn recalled.
const MARKERS: [&str; 12] = [
    "wavemarker00",
    "wavemarker01",
    "wavemarker02",
    "wavemarker03",
    "wavemarker04",
    "wavemarker05",
    "wavemarker06",
    "wavemarker07",
    "wavemarker08",
    "wavemarker09",
    "wavemarker10",
    "wavemarker11",
];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn holder_key(actor: &EntityId) -> SigningKey {
    SigningKey::from_bytes(&blake3::derive_key(
        "oneiron/test/proxy-recall-limit-holder/v1",
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
            b"recall limit actor",
        )
        .expect("recall limit actor row");
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
        .expect("recall limit pairing link");
    let key = holder_key(&actor);
    let binding = key.verifying_key().to_bytes();
    let transcript = pairing_binding_transcript(&link.code, &binding, &holder)
        .expect("recall limit binding transcript");
    let signature = key.sign(&transcript);
    let slip = vault
        .redeem_pairing_link(issuer, &link.code, &holder, binding, &signature.to_bytes())
        .expect("recall limit redeemed slip");
    (slip, key)
}

fn holder_auth(vault: &Vault, slip: &CapabilitySlip, key: &SigningKey) -> (String, String) {
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let transcript = slip
        .binding_transcript(challenge.as_bytes())
        .expect("recall limit holder transcript");
    let signature = hex(&key.sign(&transcript).to_bytes());
    let bearer = slip.to_token().expect("recall limit slip token");
    let binding =
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string();
    (format!("Bearer {bearer}"), binding)
}

fn owner_auth(vault: &Vault, issuer: &HostSlipIssuer) -> (String, String) {
    let slip = vault
        .ensure_host_root_slip(issuer)
        .expect("recall limit host root slip");
    let timestamp = vault.now_recorded_at();
    let nonce = EntityId::now().to_hex();
    let challenge = format!("oneiron-request:{timestamp}:{nonce}");
    let proof = issuer
        .binding_proof(&slip, challenge.as_bytes())
        .expect("recall limit owner proof");
    let bearer = slip.to_token().expect("recall limit owner token");
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
        .expect("recall limit request")
}

async fn send(router: Router, request: Request<Body>) -> (StatusCode, Value) {
    let response = router
        .oneshot(request)
        .await
        .expect("recall limit response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("recall limit body");
    let body: Value = serde_json::from_slice(&bytes).expect("recall limit json body");
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

/// Twelve claims that all match the turn's query, each carrying one
/// marker word. One subject serves all twelve; the text index publishes
/// once, after every claim stands.
fn seed_marker_claims(vault: &Vault) {
    let subject = EntityId::now();
    vault
        .put_entity(
            &subject,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"recall limit subject",
        )
        .expect("recall limit subject row");
    for marker in MARKERS {
        let text = format!("the harbor lighthouse keeps a brass {marker} for night crossings");
        let body = ClaimBody::new(
            SEED_PREDICATE,
            ClaimSubject::Entity(subject),
            rmpv::Value::from(text.as_str()),
            0.8,
            ClaimApprovalStatus::Auto,
            ClaimLifecycleStatus::Active,
        )
        .expect("recall limit claim body");
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
            .expect("recall limit seed claim");
        vault
            .batch()
            .text(&id, &[("body", text.as_str())])
            .commit()
            .expect("recall limit text index");
    }
    vault
        .set_indexed_idle_delay_ms(0)
        .expect("recall limit index delay");
    let published = vault
        .refresh_staged_indexed_at_idle(u64::MAX)
        .expect("recall limit index refresh");
    assert!(
        published.failed.is_empty(),
        "recall limit index publish failed: {:?}",
        published.failed
    );
}

/// The owner sets `proxy.openai.recall_limit` to `rows` through the
/// public setting door. No call here needs `--cfg oneiron_test_support`:
/// every door is public API, and the seeded vault is rooted far enough to
/// bind the embedded owner.
fn set_recall_limit(vault: &Vault, issuer: &HostSlipIssuer, rows: u32) {
    vault
        .prepare_install_signing()
        .expect("recall limit signing");
    vault
        .ensure_host_root_slip(issuer)
        .expect("recall limit root");
    vault
        .provision_engine_machine_identities(issuer)
        .expect("recall limit engine identities");
    vault
        .ensure_serving_install_profile(issuer, MachineRole::Unanswered)
        .expect("recall limit serving profile");
    let owner = vault
        .ensure_embedded_owner_actor()
        .expect("recall limit owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("recall limit owner proof");
    vault
        .set_setting(
            SettingCaller::Owner(&proof),
            SetSetting {
                key: RECALL_KEY.to_owned(),
                item: None,
                scope: SettingScope::Vault,
                mode: SettingMode::Value,
                value: Some(json!(rows)),
                expected_revision: None,
                why: None,
                check_in_ref: None,
            },
        )
        .expect("the owner sets proxy.openai.recall_limit");
}

async fn serve(vault: Arc<Vault>, base_url: &str) -> (Arc<SyncServer>, AiHost) {
    let server = SyncServer::new(
        vault,
        SyncServerConfig {
            auth_secret: Some(AUTH_SECRET.to_owned()),
            ..Default::default()
        },
    )
    .expect("recall limit server");
    let toml = format!(
        "default = \"local:test-model\"\n\
         extraction_egress = true\n\
         [providers.local]\n\
         kind = \"local-openai-compat\"\n\
         base_url = \"{base_url}\"\n"
    );
    let models = ModelsConfig::from_toml(&toml, None).expect("recall limit models");
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
    serde_json::from_value(body).expect("recall limit chat response")
}

/// One chat turn with the recall key at `rows` (`None` leaves the default):
/// how many of the twelve markers the turn's injected memory block
/// carried. Markers are counted outside the query message itself, so the
/// count is the recalled rows the block lists.
async fn injected_markers(rows: Option<u32>) -> usize {
    let dir = tempfile::tempdir().expect("recall limit dir");
    let mut config = VaultConfig::device();
    // The proxy recalls in call mode, which answers an empty partial pack once
    // the vault's call-mode deadline (100 ms by default) has passed; a cold
    // first recall in a debug test build on a loaded host misses it. This test
    // is not about the deadline, so it gets the longest one, as the voice host
    // tests do.
    config.call_mode_deadline =
        std::time::Duration::from_millis(oneiron::memory::caps::MAX_RECALL_DEADLINE_MS);
    let vault = Arc::new(Vault::open(dir.path(), config).expect("recall limit vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let fake = FakeLlm::start(Vec::new(), Some(Reply::text("the remembered answer"))).await;
    let (server, host) = serve(Arc::clone(&vault), &fake.base_url).await;
    let router = build_app(server);
    let issuer = vault
        .load_host_slip_issuer()
        .expect("recall limit host issuer");
    let actor = EntityId::now();
    let (slip, key) = pair_connector(&vault, &issuer, actor);
    seed_marker_claims(&vault);
    if let Some(rows) = rows {
        set_recall_limit(&vault, &issuer, rows);
    }
    admit_proxy(&router, &vault, &issuer, actor).await;
    let answer = chat(&router, &vault, &slip, &key).await;
    assert!(
        answer.oneiron.recall_skipped.is_none(),
        "the connector's recall setting withheld recall: {:?}",
        answer.oneiron.recall_skipped
    );
    assert!(answer.oneiron.injected, "recall found nothing to inject");
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
    let present = MARKERS
        .iter()
        .filter(|marker| {
            texts
                .iter()
                .any(|text| text != QUERY && text.contains(**marker))
        })
        .count();
    host.shutdown().await;
    present
}

/// The proxy's recall, model call and proposal poll engine futures; the
/// router runs on threads sized as the server sizes its own
/// (`ENGINE_THREAD_STACK_BYTES`), on a multi-thread runtime as `build_app`
/// asks.
#[test]
fn a_raised_proxy_recall_limit_injects_more_rows() {
    run_on_engine_stack("proxy-recall-limit-raised", || async {
        assert_eq!(
            injected_markers(Some(12)).await,
            12,
            "a limit of 12 recalls every seeded row"
        );
    });
}

#[test]
fn at_the_default_the_proxy_injects_eight_rows() {
    run_on_engine_stack("proxy-recall-limit-default", || async {
        assert_eq!(
            injected_markers(None).await,
            8,
            "the default limit of 8 recalls eight of the twelve rows"
        );
    });
}
