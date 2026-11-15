//! Public-door promise tests for the `vault.consent` family (ruling L4-23 =
//! A: each test proves a promise at the door; DOOR-FAMILIES Part 2, row 1).
//!
//! Every case drives the real route `POST /v1/core/facade/<verb>` in process
//! (`build_app` + `oneshot`): the owner on the host root credential, the
//! established self-hosted owner path, and an agent on its own paired
//! credential, enrolled through a real pairing redemption and proving its
//! holder key on every request. Each case owns its vault. No sockets, no
//! sleeps, no models.
//!
//! The promises, with their canon lines (oneiron-docs `generated/`):
//! - an approve-once press authorizes one op, now, and mints no standing
//!   grant: `oneiron/decisions/oneiron-dec-0006-unified-consent-mode.md:37`
//!   "approve_once(effect_digest) authorizes this op, now.";
//! - deny records a rejected verdict, not a grant: the same line, "Deny
//!   records a rejected verdict on the proposal's settlement.";
//! - a standing grant is a deliberate "remember", and never for a
//!   catastrophe class: `dec-0006:8` "\"Remember this\" is a bounded standing
//!   grant" and `dec-0006:132` "No standing grant, bypass grant or approve
//!   once covers it.";
//! - the registry is the review and revoke surface, and a repeat revoke is
//!   idempotent: `dec-0006:8` "a registry to review and one-tap revoke",
//!   `dec-0006:295` "A repeat revoke of a consent grant is idempotent";
//! - an agent never settles consent, mints a grant or rules on the ramp:
//!   `dec-0006:8` "By default only a holder's yes creates it" and
//!   `oneiron/core/oneiron-arch-0055-entity-merge-split-consent-ramp-v1.md:187`
//!   "Recording a ruling on a graduation proposal takes the owner's proof".
//!
//! The grantee's own renounce has its door test in
//! `consent_revoke_grantee_renounce.rs`; the graduation demotion by a policy
//! holder in `graduation_demote_holder_door.rs`. This file covers the
//! owner's side of the family and the agent's refusals.
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in the PR: the approve-once spent marker, the
//! catastrophe floor check, and the owner proof of the host doors.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! vault_consent_doors`. The test calls no test door; it needs
//! `oneiron/test-support` for `MemoryKeystore`.
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
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::consent::CATASTROPHE_FLOOR_V3;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

/// The graduation scope the ramp cases name: an agent's email follow-ups.
const RAMP_OP: &str = "send_email";
const RAMP_TARGET: &str = "client_followup";

/// One paired agent credential: its registered principal, its holder
/// signing key, its redeemed slip and the token it presents.
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

/// A fresh 64-hex digest, as an engine-emitted effect digest is spelled.
fn digest() -> String {
    let id = EntityId::now().to_hex();
    let tail = EntityId::now().to_hex();
    let mut digest = format!("{id}{tail}");
    digest.truncate(64);
    assert_eq!(digest.len(), 64, "two entity ids spell a 64-hex digest");
    digest
}

async fn served() -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-consent-doors".into()),
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
    let agent = pair_agent(&vault, &app, &issuer, "consent-doors-agent", [0x31; 32]).await;
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

/// Pairs one agent the way `token agent` does: a registered PERSON
/// principal, a principal-bound link narrowed to `core:read` and
/// `core:write`, redeemed over the real pairing route with the
/// holder-signed binding transcript.
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
    assert_eq!(
        slip.claims.actor_class.as_deref(),
        Some("agent"),
        "the redeemed slip binds an agent"
    );
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

    /// `caller` posts `verb` with `input` to its facade door: the status and
    /// the body.
    async fn post(&self, caller: Caller, verb: &str, input: Value) -> (StatusCode, Value) {
        let token = match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Agent => self.agent.token.as_str(),
        };
        let request = Request::post(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {token}"))
            .header("x-oneiron-binding", self.binding(caller))
            .header("content-type", "application/json")
            .body(Body::from(input.to_string()))
            .expect("facade request");
        let response = self
            .app
            .clone()
            .oneshot(request)
            .await
            .expect("facade response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("facade response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The owner's registry rows, with or without the revoked audit rows.
    async fn registry_rows(&self, include_revoked: bool) -> Vec<Value> {
        let (status, body) = self
            .post(
                Caller::Owner,
                "vault.consent.registry",
                json!({"limit": 500, "include_revoked": include_revoked}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner reads the registry: {body}");
        body["rows"].as_array().expect("registry rows").clone()
    }

    /// The owner's registry row for `grant`, from the audit view.
    async fn registry_row(&self, grant: &str) -> Option<Value> {
        self.registry_rows(true)
            .await
            .into_iter()
            .find(|row| row["grant_ref"].as_str() == Some(grant))
    }

    /// An action grant's bound for the paired agent over a fresh project.
    fn action_bound(&self, class: &str) -> Value {
        json!({
            "bound": {
                "actor": self.agent.principal.to_hex(),
                "class": class,
                "envelope": {
                    "project": EntityId::now().to_hex(),
                    "audience": [EntityId::now().to_hex()],
                },
            },
        })
    }

    /// The graduation scope of the paired agent's email follow-ups.
    fn ramp_scope(&self) -> Value {
        json!({
            "op_kind": RAMP_OP,
            "target_class": RAMP_TARGET,
            "actor": self.agent.principal.to_hex(),
        })
    }

    /// The owner's read of the ramp's outcome history for [`Self::ramp_scope`].
    async fn ramp_stats(&self) -> Value {
        let (status, body) = self
            .post(
                Caller::Owner,
                "vault.consent.graduation.stats",
                json!({"scope": self.ramp_scope()}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner reads the ramp: {body}");
        body
    }
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// The owner presses approve-once on one effect digest: 200, an approved
/// receipt with the approve-once reason, no grant ref and no registry row,
/// because approve-once authorizes this op, now, and mints no standing grant
/// (dec-0006:37). A second press on the same digest is refused (the spent
/// marker), and it writes nothing. Red with the seeded fault that drops the
/// spent-marker claim in `Vault::approve_once_in_txn`.
#[test]
fn an_approve_once_press_releases_one_digest_and_mints_no_grant() {
    run_on_engine_stack("consent-doors-approve-once", || async {
        let served = served().await;
        let before = served.registry_rows(true).await;
        let effect = digest();

        let (status, body) = served
            .post(
                Caller::Owner,
                "vault.consent.approve_once",
                json!({"effect_digest": effect}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner's press: {body}");
        assert_eq!(body["outcome"].as_str(), Some("approved"), "{body}");
        assert_eq!(
            body["reason_code"].as_str(),
            Some("gate.consent.approve_once"),
            "{body}"
        );
        assert!(body["grant_ref"].is_null(), "approve-once names no grant: {body}");
        assert!(
            body["decision_ref"].as_str().is_some_and(|id| !id.is_empty()),
            "the press lands a Gate decision: {body}"
        );
        assert_eq!(
            served.registry_rows(true).await,
            before,
            "approve-once mints no standing row"
        );

        let (status, again) = served
            .post(
                Caller::Owner,
                "vault.consent.approve_once",
                json!({"effect_digest": effect}),
            )
            .await;
        assert_eq!(
            (status, error_code(&again)),
            (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
            "a second press on a spent digest is refused: {again}"
        );
        assert_eq!(
            served.registry_rows(true).await,
            before,
            "the refused press writes nothing"
        );
    });
}

/// The owner denies one effect digest: 200, a denied receipt with the denied
/// reason and no grant ref, and the registry is unchanged: deny records a
/// rejected verdict, never a grant (dec-0006:37).
#[test]
fn a_denial_records_a_denied_verdict_and_no_grant() {
    run_on_engine_stack("consent-doors-deny", || async {
        let served = served().await;
        let before = served.registry_rows(true).await;

        let (status, body) = served
            .post(
                Caller::Owner,
                "vault.consent.deny",
                json!({"effect_digest": digest()}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner's denial: {body}");
        assert_eq!(body["outcome"].as_str(), Some("denied"), "{body}");
        assert_eq!(
            body["reason_code"].as_str(),
            Some("gate.consent.denied"),
            "{body}"
        );
        assert!(body["grant_ref"].is_null(), "a denial names no grant: {body}");
        assert_eq!(
            served.registry_rows(true).await,
            before,
            "a denial adds no registry row"
        );
    });
}

/// The owner's standing grant is a deliberate "remember" that the registry
/// lists as active (dec-0006:8). For every catastrophe floor class the same
/// door refuses the grant and writes nothing: no standing grant covers a
/// catastrophe row (dec-0006:132). Red with the seeded fault that skips the
/// floor check in `Vault::create_standing_grant_in_txn`.
#[test]
fn a_standing_grant_is_remembered_but_never_for_a_catastrophe_class() {
    run_on_engine_stack("consent-doors-standing", || async {
        let served = served().await;
        let before = served.registry_rows(true).await;

        for class in CATASTROPHE_FLOOR_V3 {
            let class = class.as_str();
            let (status, body) = served
                .post(
                    Caller::Owner,
                    "vault.consent.create_standing_grant",
                    served.action_bound(class),
                )
                .await;
            assert_eq!(
                (status, error_code(&body)),
                (StatusCode::BAD_REQUEST, Some("BAD_REQUEST")),
                "a standing grant for catastrophe class {class} is refused: {body}"
            );
        }
        assert_eq!(
            served.registry_rows(true).await,
            before,
            "no refused catastrophe grant reaches the registry"
        );

        let (status, body) = served
            .post(
                Caller::Owner,
                "vault.consent.create_standing_grant",
                served.action_bound("channel_send"),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner's standing grant: {body}");
        assert_eq!(body["outcome"].as_str(), Some("approved"), "{body}");
        assert_eq!(
            body["reason_code"].as_str(),
            Some("gate.consent.standing_created"),
            "{body}"
        );
        let grant = body["grant_ref"].as_str().expect("grant ref").to_owned();
        let row = served
            .registry_row(&grant)
            .await
            .expect("the registry lists the new grant");
        assert_eq!(row["status"].as_str(), Some("active"), "{row}");
        assert_eq!(
            served.registry_rows(true).await.len(),
            before.len() + 1,
            "exactly one row is added"
        );
    });
}

/// The owner revokes a standing grant from the registry: 200 and a revoked
/// receipt, the row leaves the active view and stays in the audit view as
/// revoked. A repeat revoke succeeds with the original receipt and
/// `already_revoked: true` (dec-0006:295).
#[test]
fn the_owners_repeat_revoke_is_idempotent() {
    run_on_engine_stack("consent-doors-revoke", || async {
        let served = served().await;
        let (status, created) = served
            .post(
                Caller::Owner,
                "vault.consent.create_standing_grant",
                served.action_bound("channel_send"),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner's standing grant: {created}");
        let grant = created["grant_ref"].as_str().expect("grant ref").to_owned();

        let (status, revoked) = served
            .post(Caller::Owner, "vault.consent.revoke", json!({"grant": grant}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner's revoke: {revoked}");
        assert_eq!(revoked["outcome"].as_str(), Some("revoked"), "{revoked}");
        assert_eq!(
            revoked["reason_code"].as_str(),
            Some("gate.consent.revoked"),
            "{revoked}"
        );
        assert_ne!(
            revoked["already_revoked"].as_bool(),
            Some(true),
            "the first revoke writes: {revoked}"
        );
        let decision = revoked["decision_ref"]
            .as_str()
            .expect("the revoke's decision ref")
            .to_owned();
        assert!(
            served
                .registry_rows(false)
                .await
                .iter()
                .all(|row| row["grant_ref"].as_str() != Some(grant.as_str())),
            "the revoked grant leaves the active registry"
        );
        let row = served
            .registry_row(&grant)
            .await
            .expect("the audit view keeps the revoked row");
        assert_eq!(row["status"].as_str(), Some("revoked"), "{row}");

        let (status, again) = served
            .post(Caller::Owner, "vault.consent.revoke", json!({"grant": grant}))
            .await;
        assert_eq!(status, StatusCode::OK, "a repeat revoke succeeds: {again}");
        assert_eq!(again["already_revoked"].as_bool(), Some(true), "{again}");
        assert_eq!(
            again["decision_ref"].as_str(),
            Some(decision.as_str()),
            "a repeat revoke returns the original receipt: {again}"
        );
        assert_eq!(again["outcome"].as_str(), Some("revoked"), "{again}");
    });
}

/// The owner records a ruling on the agent's graduation proposal: 200, and
/// the ramp's history counts it (arch-0055:187).
#[test]
fn the_owner_records_a_ruling_on_the_ramp() {
    run_on_engine_stack("consent-doors-ramp-owner", || async {
        let served = served().await;
        let (status, body) = served
            .post(
                Caller::Owner,
                "vault.consent.graduation.outcome",
                json!({"scope": served.ramp_scope(), "outcome": "approved_untouched"}),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "the owner's ruling: {body}");
        assert_eq!(body["untouched_streak"].as_u64(), Some(1), "{body}");
        let stats = served.ramp_stats().await;
        assert_eq!(
            stats["untouched_streak"].as_u64(),
            Some(1),
            "the ramp keeps the owner's ruling: {stats}"
        );
    });
}

/// The agent, on its own verified credential, posts each owner door of the
/// family with a well-formed input. Each answers 403 `FORBIDDEN`, and none
/// writes: the registry is unchanged, the ramp holds no ruling, and the
/// digest the agent pressed is still unspent, so the owner's own press on it
/// lands. An agent never settles consent, mints a grant or rules on the
/// ramp (dec-0006:8; arch-0055:187). Red with the seeded fault that lets
/// the host doors' owner proof fall back to the embedded owner.
#[test]
fn an_agent_is_refused_at_every_owner_door_of_the_family() {
    run_on_engine_stack("consent-doors-agent", || async {
        let served = served().await;
        let before = served.registry_rows(true).await;
        let pressed = digest();
        let rows: [(&str, Value); 8] = [
            (
                "vault.consent.approve_once",
                json!({"effect_digest": pressed}),
            ),
            ("vault.consent.deny", json!({"effect_digest": digest()})),
            (
                "vault.consent.create_standing_grant",
                served.action_bound("channel_send"),
            ),
            (
                "vault.consent.registry",
                json!({"limit": 500, "include_revoked": true}),
            ),
            ("vault.consent.graduation.offers", json!({})),
            (
                "vault.consent.graduation.stats",
                json!({"scope": served.ramp_scope()}),
            ),
            (
                "vault.consent.graduation.outcome",
                json!({"scope": served.ramp_scope(), "outcome": "approved_untouched"}),
            ),
            (
                "vault.consent.graduation.answer",
                json!({"scope": served.ramp_scope(), "answer": "auto"}),
            ),
        ];
        for (verb, input) in rows {
            let (status, body) = served.post(Caller::Agent, verb, input).await;
            assert_eq!(
                (status, error_code(&body)),
                (StatusCode::FORBIDDEN, Some("FORBIDDEN")),
                "the agent is refused at {verb}: {body}"
            );
        }

        assert_eq!(
            served.registry_rows(true).await,
            before,
            "no refused agent call reaches the registry"
        );
        let stats = served.ramp_stats().await;
        assert!(
            stats.is_null() || stats["untouched_streak"].as_u64() == Some(0),
            "the ramp holds no ruling the agent posted: {stats}"
        );
        let (status, body) = served
            .post(
                Caller::Owner,
                "vault.consent.approve_once",
                json!({"effect_digest": pressed}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the agent's refused press spent nothing: {body}"
        );
    });
}
