//! FIX-LIST 23279 ([AGENT-PAIR-MINT-FAIL-401]): an owner's pairing link for
//! a named agent mints the agent's default read Grant in the issue's own
//! writer, and a mint that fails refuses the link. On main the refusal is
//! the pairing door's unexplained 401, so the owner cannot tell a missing
//! carrier from a bad credential; the mint's refusals must name their rule,
//! a 409, as the grants door answers the same failure.
//!
//! The carrier-less install is this install after the owner removes its own
//! machine, terminally: no live machine profile stands under its install
//! key, so the mint fails `AGENT_GRANT_ACT_NO_CARRIER`. The control links
//! (a carrier-live agent link, a carrier-less human link) pass on main too.
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test agent_pair_mint_refusal_status`.
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
use engine_stack::run_on_engine_stack;
use oneiron::authority::{ActSurface, CapabilitySlip, HostSlipIssuer, MachineRole};
use oneiron::consent::ConsentRegistryQuery;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::store::GateDecisionId;
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

struct OwnerClient {
    app: Router,
    vault: Arc<Vault>,
    issuer: HostSlipIssuer,
    slip: CapabilitySlip,
    token: String,
    _dir: tempfile::TempDir,
}

impl OwnerClient {
    /// A served device vault, rooted under its auth secret, holding this
    /// install's live machine profile from its first start (FIX 4648), with
    /// the host root slip its owner requests ride.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("fresh vault"));
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        vault.prepare_install_signing().expect("install signing");
        let server = Arc::new(
            SyncServer::new(
                Arc::clone(&vault),
                SyncServerConfig {
                    auth_secret: Some("agent-pair-mint-refusal".into()),
                    ..Default::default()
                },
            )
            .expect("serving vault"),
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
            _dir: dir,
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

/// The pairing Scope `oneiron token read` gives: every world, `core:read`.
fn agent_link_scope() -> Scope {
    let mut scope = Scope::top();
    scope.verbs = ScopeAxis::Some(BTreeSet::from(["core:read".to_owned()]));
    scope
}

/// The owner removes this install's own machine, terminally: no live machine
/// profile stands under its install key, so an owner act this install carries
/// next, the default-Grant mint included, has no carrier.
fn remove_own_machine(vault: &Vault) {
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let proof = vault
        .authenticate_owner(owner, &owner.to_hex(), true, GateDecisionId::now())
        .expect("owner proof");
    let machine = vault
        .local_machine()
        .expect("local machine read")
        .expect("this install's machine")
        .id;
    vault
        .set_machine_role(
            &proof,
            ActSurface::ThisInstall,
            machine,
            MachineRole::Removed,
            None,
        )
        .expect("owner removes this install's machine");
}

/// How many live owner-agent Grants of the registry name `holder`.
fn grants_naming(vault: &Vault, holder: EntityId) -> usize {
    vault
        .consent_registry(ConsentRegistryQuery::new(1_000, false))
        .expect("owner's consent registry")
        .rows
        .into_iter()
        .filter(|row| {
            row.agent_grant
                .as_ref()
                .is_some_and(|grant| grant.agent == holder)
        })
        .count()
}

#[test]
fn agent_pairing_link_without_a_carrier_names_the_mint_refusal() {
    run_on_engine_stack(
        "agent-pair-mint-refusal",
        carrier_less_agent_link_is_a_named_conflict,
    );
}

/// Red on main, which answers the refused link 401: the mint's missing
/// carrier must read as a named 409, and the refused link mints no Grant.
async fn carrier_less_agent_link_is_a_named_conflict() {
    let client = OwnerClient::new();
    let agent = client
        .vault
        .ensure_agent_principal("pair_mint_refusal_agent")
        .expect("named agent principal");
    remove_own_machine(&client.vault);
    let (status, body) = client
        .post(
            "/v1/core/pairing/links",
            json!({
                "scope": agent_link_scope(),
                "lifetime_secs": 600,
                "principal": {"holder_ref": agent.to_hex(), "actor_class": "agent"},
            }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"]["code"], "INVALID_STATE", "{body}");
    let message = body["error"]["message"]
        .as_str()
        .expect("a refusal message");
    assert!(
        message.contains("no live machine profile"),
        "the refusal names the mint's missing carrier; body={body}"
    );
    assert_eq!(
        grants_naming(&client.vault, agent),
        0,
        "the refused link minted no Grant; body={body}"
    );
}

#[test]
fn agent_pairing_link_with_a_carrier_still_mints_its_grant() {
    run_on_engine_stack("agent-pair-mint-control", carrier_agent_link_mints);
}

/// Control for the refusal above: with this install's machine profile live,
/// the same link issues and mints the agent's one default Grant. Passes on
/// main too.
async fn carrier_agent_link_mints() {
    let client = OwnerClient::new();
    let agent = client
        .vault
        .ensure_agent_principal("pair_mint_control_agent")
        .expect("named agent principal");
    let (status, body) = client
        .post(
            "/v1/core/pairing/links",
            json!({
                "scope": agent_link_scope(),
                "lifetime_secs": 600,
                "principal": {"holder_ref": agent.to_hex(), "actor_class": "agent"},
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["code"].is_string(), "the link issued; body={body}");
    assert_eq!(
        grants_naming(&client.vault, agent),
        1,
        "the issued link minted the agent's one default Grant; body={body}"
    );
}

#[test]
fn human_pairing_link_without_a_carrier_still_issues() {
    run_on_engine_stack(
        "agent-pair-mint-human-guard",
        carrier_less_human_link_issues,
    );
}

/// Guard: removing the carrier refuses only the agent-Grant mint, not the
/// pairing door itself. An owner's link for a holder no Grant names, who
/// mints nothing, still issues. Passes on main too.
async fn carrier_less_human_link_issues() {
    let client = OwnerClient::new();
    remove_own_machine(&client.vault);
    let owner = client.vault.ensure_embedded_owner_actor().expect("owner");
    let (status, body) = client
        .post(
            "/v1/core/pairing/links",
            json!({
                "scope": agent_link_scope(),
                "lifetime_secs": 600,
                "principal": {"holder_ref": owner.to_hex(), "actor_class": "human"},
            }),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["code"].is_string(), "the link issued; body={body}");
}
