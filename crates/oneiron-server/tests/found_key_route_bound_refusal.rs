//! L6-03-FOUND-KEY-ROUTE-BOUND-500 (Engine RULING NEXT-ROW-18 B, 14 Nov):
//! an owner found-key route answers an engine refusal of kind
//! `InvalidConsentBound` as the 409 `refused` a refused owner act answers,
//! in the engine's own words, never as a 500.
//!
//! The owner rules a found key not a secret through the engine; asking
//! again over HTTP, at `POST /v1/owner/secrets/found/not-a-secret` and at
//! `/keep-as-text`, meets the engine's "already ruled" refusal. On
//! unmodified main both answer 500 ("owner action failed").
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models).
//!
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron-server --all-features --features oneiron/test-support --test found_key_route_bound_refusal`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::sync::Arc;

use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::consent::AuthenticatedOwner;
use oneiron::memory::StructuralPutInput;
use oneiron::store::GateDecisionId;
use oneiron::{EdgeActorClass, EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// A GitHub token the door's text rules place by its span.
const TOKEN: &str = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";

/// The engine's refusal of a second ruling on a key ruled not a secret.
const ALREADY_RULED: &str = "the owner ruled this key no secret";

/// A rooted server on its own device keystore: the host's root credential,
/// which acts as the vault owner over HTTP, and the owner's engine proof.
struct Served {
    _dir: tempfile::TempDir,
    server: Arc<SyncServer>,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    root: CapabilitySlip,
    root_token: String,
    /// The vault's embedded owner, who writes the record.
    owner_id: EntityId,
    owner: AuthenticatedOwner,
}

fn served() -> Served {
    let dir = tempfile::tempdir().expect("FIXTURE: a vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("FIXTURE: a vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    vault
        .prepare_install_signing()
        .expect("FIXTURE: install signing");
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("found-key-route-bound-refusal".to_owned()),
                ..Default::default()
            },
        )
        .expect("FIXTURE: a server"),
    );
    let issuer = vault
        .bootstrap_host_slip_issuer()
        .expect("FIXTURE: the host issuer");
    let root = vault
        .ensure_host_root_slip(&issuer)
        .expect("FIXTURE: the host root slip");
    let root_token = root.to_token().expect("FIXTURE: the root token");
    // The owner's acts are carried by this install's live machine profile,
    // as a serving start or `init` enrols it.
    vault
        .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
        .expect("FIXTURE: this install's live machine profile");
    let owner_id = vault
        .ensure_embedded_owner_actor()
        .expect("FIXTURE: the embedded owner");
    let owner = vault
        .authenticate_owner(owner_id, &owner_id.to_hex(), true, GateDecisionId::now())
        .expect("FIXTURE: the owner's proof");
    Served {
        _dir: dir,
        server,
        vault,
        issuer,
        root,
        root_token,
        owner_id,
        owner,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Served {
    /// An EVENT the owner writes, whose notes hold the token.
    fn write_event(&self) -> EntityId {
        let receipt = self
            .vault
            .memory(self.owner_id, EdgeActorClass::Human)
            .put_structural(&StructuralPutInput {
                id: None,
                kind: "EVENT".to_owned(),
                body: json!({
                    "name": "release",
                    "notes": format!("deploy with token={TOKEN}"),
                }),
                text_fields: None,
                edges: None,
                occurred_at: 1,
                learned_at: None,
            })
            .unwrap_or_else(|error| panic!("FIXTURE: the owner writes an EVENT: {error:?}"));
        EntityId::from_hex(&receipt.id_hex).expect("FIXTURE: the EVENT's id")
    }

    /// The handle of the key the mask lifted out of `record`, from the
    /// owner's found-key list.
    fn found_handle(&self, record: &EntityId) -> String {
        self.vault
            .found_keys(&self.owner, true, 10)
            .expect("FIXTURE: the owner's found-key list")
            .into_iter()
            .find(|notice| notice.record == *record)
            .and_then(|notice| notice.keys.into_iter().next())
            .map(|key| key.handle)
            .expect("FIXTURE: the mask lifted the token into a found key")
    }

    /// The root credential's holder proof for one request.
    fn root_binding(&self) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = hex(&self
            .issuer
            .binding_proof(&self.root, challenge.as_bytes())
            .expect("FIXTURE: the root's holder proof"));
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    /// `POST /v1/owner/secrets/found/<route>` of `handle` as the owner: the
    /// status and the JSON answer (the text, when it is not JSON).
    async fn answer(&self, route: &str, handle: &str) -> (StatusCode, Value) {
        let response = build_app(Arc::clone(&self.server))
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/owner/secrets/found/{route}"))
                    .header("Authorization", format!("Bearer {}", self.root_token))
                    .header("x-oneiron-binding", self.root_binding())
                    .header("Content-Type", "application/json")
                    .body(Body::from(json!({ "handle": handle }).to_string()))
                    .expect("FIXTURE: a request"),
            )
            .await
            .expect("a response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1_048_576)
            .await
            .expect("a response body");
        let answer = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, answer)
    }
}

#[test]
fn a_ruling_on_a_key_already_ruled_answers_409_in_the_engines_words() {
    run_on_engine_stack("found-key-bound-409", ruling_on_a_ruled_key);
}

async fn ruling_on_a_ruled_key() {
    let served = served();
    let record = served.write_event();
    let handle = served.found_handle(&record);
    served
        .vault
        .rule_found_key_not_a_secret(&served.owner, ActSurface::ThisInstall, &handle)
        .expect("FIXTURE: the owner rules the key not a secret through the engine");

    for route in ["not-a-secret", "keep-as-text"] {
        let (status, body) = served.answer(route, &handle).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "{route}: a ruling on a key already ruled is a refused act, not a server fault: {body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.contains(ALREADY_RULED),
            "{route}: the answer carries the engine's words: {body}"
        );
    }
}
