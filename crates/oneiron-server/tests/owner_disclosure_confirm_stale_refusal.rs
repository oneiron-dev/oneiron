//! A stale disclosure confirm names the refusal, never a server fault
//! ([DISCLOSURE-CONFIRM-STALE-500]).
//!
//! `POST /v1/owner/disclosure/confirm` on an offer that is missing, settled,
//! expired or changed answers 409 `INVALID_STATE` with the
//! `consent_widen_proposal` state, as the core widen route does, so an
//! owner's double-click reads as the engine's refusal "widen proposal is
//! stale, changed, or resolved", not an `INTERNAL_SERVER_ERROR`.
//!
//! On unmodified main both confirms below answer 500 ("owner action failed"):
//! `owner_error` has no `InvalidConsentGrantRow` / `InvalidConsentBound` arm.
//! The second confirm of a real offer is the row's double-click case; the
//! unknown-ref confirm is the same arm through the missing-row path.
//!
//! Deterministic: in-process vault and router (`oneshot`, no TCP ports, no
//! sleeps, no models). The offer is filed by the engine itself
//! (`offer_contact_disclosure_as_engine`), so the test needs no agent slips.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron-server --all-features --features oneiron/test-support
//! --test owner_disclosure_confirm_stale_refusal`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::path::Path;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{CapabilitySlip, HostSlipIssuer};
use oneiron::consent::ContactDisclosureOffer;
use oneiron::counterparty_contact::CounterpartyContactRecord;
use oneiron::edge::EdgeActorClass;
use oneiron::federation::Scope;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::{EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const CONFIRM: &str = "/v1/owner/disclosure/confirm";

struct OwnerClient {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
}

impl OwnerClient {
    fn new(path: &Path) -> Self {
        let vault = Arc::new(Vault::open(path, VaultConfig::device()).expect("open fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("disclosure-confirm-stale".into()),
                    ..Default::default()
                },
            )
            .expect("create owner server"),
        );
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        let token = slip.to_token().expect("owner slip token");
        Self {
            app: build_app(server),
            vault,
            issuer,
            slip,
            token,
        }
    }

    async fn post(&self, path: &str, input: Value) -> (StatusCode, Value) {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature: String = self
            .issuer
            .binding_proof(&self.slip, challenge.as_bytes())
            .expect("fresh owner holder proof")
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let token = &self.token;
        let request = Request::post(path)
            .header("authorization", format!("Bearer {token}"))
            .header(
                "x-oneiron-binding",
                json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string(),
            )
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("owner JSON request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("owner response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("owner response body");
        let body = serde_json::from_slice(&bytes).expect("owner response JSON");
        (status, body)
    }
}

/// The stale-proposal refusal every stale confirm carries.
fn assert_stale_proposal(status: StatusCode, body: &Value) {
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "INVALID_STATE", "{body}");
    assert_eq!(
        body["error"]["details"]["state"], "consent_widen_proposal",
        "{body}"
    );
}

#[test]
fn confirm_unknown_offer_answers_stale_proposal() {
    run_on_engine_stack("disclosure-confirm-unknown", || async {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let client = OwnerClient::new(dir.path());
        // Well-formed (64 lowercase hex) but filed nowhere: the shape gate
        // passes it and the table read misses, raising InvalidConsentGrantRow.
        let (status, body) = client
            .post(
                CONFIRM,
                json!({
                    "proposal_ref": "0".repeat(64),
                    "expected_delta": "00",
                    "outcome": "deny",
                }),
            )
            .await;
        assert_stale_proposal(status, &body);
    });
}

#[test]
fn confirm_settled_offer_answers_stale_proposal() {
    run_on_engine_stack("disclosure-confirm-settled", || async {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let client = OwnerClient::new(dir.path());
        // A new, active contact of a new PERSON: a party nobody cleared.
        let now = client.vault.now_recorded_at();
        let person = EntityId::now();
        let mut entity = Vec::new();
        rmpv::encode::write_value(
            &mut entity,
            &rmpv::Value::Map(vec![(
                rmpv::Value::from("name"),
                rmpv::Value::from("Reader"),
            )]),
        )
        .expect("the person's PERSON body");
        client
            .vault
            .put_entity(
                &person,
                ENTITY_TYPE_PERSON,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &entity,
            )
            .expect("the person's PERSON row");
        let contact = EntityId::now();
        client
            .vault
            .create_counterparty_contact(
                &contact,
                &CounterpartyContactRecord::public(
                    person,
                    "reader@example.com",
                    client.vault.now_recorded_at(),
                )
                .expect("the contact's record"),
            )
            .expect("the contact's row");
        // The engine's own offer of the whole scope for the contact, lapsing
        // in ten minutes of vault time and addressed to this vault's owner.
        let agent = client
            .vault
            .ensure_agent_principal("stale-refusal-offerer")
            .expect("the offering agent");
        let owner = client
            .vault
            .ensure_embedded_owner_actor()
            .expect("the embedded owner");
        let filed = client
            .vault
            .offer_contact_disclosure_as_engine(
                WriteActor::new(agent, EdgeActorClass::Agent),
                ContactDisclosureOffer {
                    contact_ref: contact,
                    scope: Scope::top(),
                    purpose: "share the reading group's notes".to_owned(),
                    channel: "room:reading-group".to_owned(),
                    beneficiary_ref: contact.to_hex(),
                    ask_ref: None,
                },
                &owner.to_hex(),
                client.vault.now_recorded_at() + 600,
            )
            .expect("file the offer");
        let delta: String = filed
            .canonical_delta
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let input = json!({
            "proposal_ref": filed.proposal_ref,
            "expected_delta": delta,
            "outcome": "standing",
        });
        let (status, body) = client.post(CONFIRM, input.clone()).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["act"], "standing", "{body}");
        // The double-click: the settled offer takes no second answer.
        let (status, body) = client.post(CONFIRM, input).await;
        assert_stale_proposal(status, &body);
    });
}
