//! The owner's project mint at its served facade rows (FIX
//! [OWNER-PROJECT-MINT-DOOR]): `vault.projects.mint` and
//! `vault.projects.minted`.
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! the owner on the host root credential, and an agent on its own paired
//! credential, enrolled through a real pairing redemption and proving its
//! holder key on every request, as `machine_name_doors.rs` does. Each case
//! owns its vault. No sleeps, no models.
//!
//! The promises:
//! - S1: the owner mints the lane under the root and its child under the
//!   lane at the row, and reads both back;
//! - S2: owner proof only (chosen by the Engine 28 Nov): an agent is refused
//!   at both rows even with a live Grant that lists both verbs, and its
//!   attempt mints nothing.
//!
//! Red on main: neither row exists there (404).
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! project_owner_mint_doors`. It calls no test door; the cfg flag builds
//! `MemoryKeystore`.
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
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, MachineRole, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// One paired agent credential: its principal, its holder signing key, its
/// redeemed slip and the token it presents.
struct Agent {
    principal: EntityId,
    holder: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// A served vault with its owner's host root credential and one paired
/// agent.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    agent: Agent,
}

/// Who posts a request.
#[derive(Clone, Copy)]
enum Caller {
    Owner,
    Agent,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// A served vault with this install's machine profile enrolled, as a
/// serving start enrols it, and one paired agent.
async fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("project-owner-mint-doors".into()),
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
    let app = build_app(server);
    let agent = pair_agent(&vault, &app, &issuer, "project-mint-agent", [0x5e; 32]).await;
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        agent,
    }
}

/// Pairs one agent the way `token agent` does: a registered principal, a
/// principal-bound link narrowed to `core:read` and `core:write`, redeemed
/// over the real pairing route with the holder-signed binding transcript.
async fn pair_agent(
    vault: &Vault,
    app: &Router,
    issuer: &HostSlipIssuer,
    name: &str,
    seed: [u8; 32],
) -> Agent {
    let principal = vault.ensure_agent_principal(name).expect("agent principal");
    let holder = SigningKey::from_bytes(&seed);
    let binding_key = holder.verifying_key().to_bytes();
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from([
        "core:read".to_owned(),
        "core:write".to_owned(),
    ]));
    let link = vault
        .issue_pairing_link_for_principal(
            issuer,
            scope,
            3600,
            PairingPrincipal {
                holder_ref: Some(principal.to_hex()),
                actor_class: Some("agent".to_owned()),
                org_ref: None,
                write_facet: None,
                ..Default::default()
            },
        )
        .expect("pairing link");
    let transcript = pairing_binding_transcript(&link.code, &binding_key, &principal.to_hex())
        .expect("pairing transcript");
    let signature = hex(&holder.sign(&transcript).to_bytes());
    let request = Request::post("/v1/core/pairing/redeem")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "code": link.code,
                "holder_ref": principal.to_hex(),
                "binding_key": hex(&binding_key),
                "signature": signature,
            })
            .to_string(),
        ))
        .expect("pairing redeem request");
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("pairing redeem response");
    assert_eq!(response.status(), StatusCode::OK, "pairing redeem status");
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("pairing redeem body");
    let body: Value = serde_json::from_slice(&bytes).expect("pairing redeem JSON");
    let token = body["token"].as_str().expect("paired token").to_owned();
    let slip = CapabilitySlip::from_token(&token).expect("paired slip");
    Agent {
        principal,
        holder,
        slip,
        token,
    }
}

impl Served {
    /// The request binding `caller` signs afresh for one request.
    fn binding(&self, caller: Caller) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let signature = match caller {
            Caller::Owner => hex(&self
                .issuer
                .binding_proof(&self.owner_slip, challenge.as_bytes())
                .expect("owner holder proof")),
            Caller::Agent => {
                let transcript = self
                    .agent
                    .slip
                    .binding_transcript(challenge.as_bytes())
                    .expect("agent binding transcript");
                hex(&self.agent.holder.sign(&transcript).to_bytes())
            }
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    fn token(&self, caller: Caller) -> &str {
        match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Agent => self.agent.token.as_str(),
        }
    }

    /// `caller` posts `verb` with `input` to its facade row: the status and
    /// the body.
    async fn post(&self, caller: Caller, verb: &str, input: Value) -> (StatusCode, Value) {
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", self.token(caller)))
            .header("x-oneiron-binding", self.binding(caller))
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("row request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("row response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("row response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The owner's `vault.projects.minted`, asserted 200: its rows.
    async fn minted(&self) -> Vec<Value> {
        let (status, body) = self
            .post(Caller::Owner, "vault.projects.minted", json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner reads the rows: {body}");
        body["projects"].as_array().cloned().unwrap_or_default()
    }
}

/// S1.
#[test]
fn the_owner_mints_and_reads_at_the_rows() {
    run_on_engine_stack("project-owner-mint", || async {
        let served = served().await;
        let root = served.vault.root_project().expect("root project");
        let (status, lane) = served
            .post(
                Caller::Owner,
                "vault.projects.mint",
                json!({"name": "neon-lane", "intent_key": "lane-project-1"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner mints the lane: {lane}");
        assert_eq!(lane["replayed"], false, "{lane}");
        assert_eq!(lane["project"]["parent"], json!(root), "{lane}");
        let lane_id = lane["project"]["project"].clone();
        let (status, neon) = served
            .post(
                Caller::Owner,
                "vault.projects.mint",
                json!({"name": "neon", "parent": lane_id, "intent_key": "neon-project-1"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner mints the child: {neon}");
        assert_eq!(neon["project"]["parents"], json!([lane_id]), "{neon}");

        let minted = served.minted().await;
        let names: Vec<_> = minted.iter().map(|row| row["name"].clone()).collect();
        assert_eq!(names, vec![json!("neon-lane"), json!("neon")], "{minted:?}");
        assert_eq!(minted[1]["parent"], lane_id, "{minted:?}");
    });
}

/// S2.
#[test]
fn an_agent_reaches_neither_row_even_with_a_grant() {
    run_on_engine_stack("project-owner-mint-agent", || async {
        let served = served().await;
        let (status, minted) = served
            .post(
                Caller::Owner,
                "vault.agents.grants.mint",
                json!({
                    "agent": served.agent.principal.to_hex(),
                    "authority_scope": {
                        "worlds": {"kind": "all"},
                        "facets": {"kind": "all"},
                        "bands": {"kind": "all"},
                        "audience": {"kind": "all"},
                        "verbs": {"kind": "some", "values": [
                            "read",
                            "vault.projects.mint",
                            "vault.projects.minted",
                        ]},
                        "sensitivity": {"kind": "at_most", "value": "restricted"},
                    },
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the owner mints the agent a Grant listing both verbs: {minted}"
        );
        for (verb, input) in [
            (
                "vault.projects.mint",
                json!({"name": "agent-lane", "intent_key": "agent-lane-1"}),
            ),
            ("vault.projects.minted", json!({})),
        ] {
            let (status, body) = served.post(Caller::Agent, verb, input).await;
            assert_eq!(
                (status, error_code(&body)),
                (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
                "the agent is refused at {verb}: {body}"
            );
        }
        assert!(
            served.minted().await.is_empty(),
            "the agent's attempt minted nothing"
        );
    });
}
