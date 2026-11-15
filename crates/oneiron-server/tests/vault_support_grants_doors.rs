//! Public-door promise tests for the `vault.support_grants` family (ruling
//! L4-23 = A: each test proves a promise at the door; DOOR-FAMILIES Part 2,
//! row 11).
//!
//! Every case drives the real routes in process (`build_app` + `oneshot`):
//! `POST /v1/core/facade/<verb>` for `vault.support_grants.mint`, `.list`
//! and `.revoke`, and the support party's own calls on the credential the
//! mint answers. Callers: the owner on the host root credential; the support
//! party on the minted slip, proving its own key on every request; an agent
//! on its own paired credential; and, on a hosted vault, the operator's
//! root. Each case owns its vault. No sleeps, no models.
//!
//! The promises, with their canon lines (oneiron-docs `generated/`,
//! `oneiron/backend/oneiron-arch-0006a-conversations-api-core.md`):
//! - the customer gives our support person or agent a grant to fix
//!   something inside the vault (`:403`): the owner mints it to the support
//!   party's own key, inside explicit bounds, and the credential reaches
//!   those bounds and nothing more; wider bounds, a longer life, an owner as
//!   holder or a key already held are refused;
//! - the grant is time-limited and revocable (`:403`): a revoke ends it at
//!   once and its deadline ends it on the vault's clock; what support read
//!   is not recalled;
//! - an owner act by the operator root gets the typed refusal
//!   `HOST_ACTION_REQUIRES_SUPPORT_GRANT` (`:406`);
//! - the grant doors are the owner's: a support credential never passes
//!   them, its own grant included, nor does an agent
//!   (`crates/oneiron-server/src/api/facade/support_grant_doors.rs:1-17`).
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in the PR.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! vault_support_grants_doors`. The test calls no test door; it needs
//! `oneiron/test-support` for `MemoryKeystore`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode},
};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::run_on_engine_stack;
use oneiron::authority::{
    CapabilitySlip, HostSlipIssuer, PairingPrincipal, pairing_binding_transcript,
};
use oneiron::federation::{Scope, ScopeAxis, ScopeId, Sensitivity, SensitivityCeiling};
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::store::ports::ManualClock;
use oneiron::{EntityId, HostingPrivacyPosture, TimeRange, Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::{build_app, config::SyncServerConfig, server::SyncServer};
use serde_json::{Value, json};
use tower::ServiceExt;

const MINT: &str = "vault.support_grants.mint";
const LIST: &str = "vault.support_grants.list";
const REVOKE: &str = "vault.support_grants.revoke";
/// A Read verb any verified credential may call: it answers the caller's
/// own ceiling (`memory.credential_ceiling`).
const CEILING: &str = "vault.scope.ceiling";

/// The typed refusal an operator root's owner act gets on a hosted vault.
const HOST_ACTION_REFUSED: &str = "HOST_ACTION_REQUIRES_SUPPORT_GRANT";

/// The longest support grant, in seconds (`SUPPORT_GRANT_MAX_TTL_SECS`).
const MAX_TTL_SECS: u64 = 86_400;

/// One credential a test holds: its slip, its holder key and its token.
struct Holder {
    key: SigningKey,
    slip: CapabilitySlip,
    token: String,
}

/// A served vault with its owner's host root credential, the owner's own
/// PERSON, a live support PERSON who owns nothing here, and (on a
/// self-hosted vault) one paired agent.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    app: Router,
    issuer: HostSlipIssuer,
    owner_slip: CapabilitySlip,
    owner_token: String,
    owner_person: EntityId,
    support_person: EntityId,
    agent: Option<Holder>,
}

/// Who sends a request.
#[derive(Clone, Copy)]
enum Caller<'a> {
    /// The owner on the host root credential (on a hosted vault, the
    /// operator's root).
    Owner,
    /// The paired agent.
    Agent,
    /// The support party on a minted grant.
    Support(&'a Holder),
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// A self-hosted served vault on the wall clock.
async fn served() -> Served {
    served_with(VaultConfig::device(), true).await
}

/// A served vault opened with `config`; `pair` pairs one agent.
async fn served_with(config: VaultConfig, pair: bool) -> Served {
    let dir = tempfile::tempdir().expect("temporary vault directory");
    let vault = Arc::new(Vault::open(dir.path(), config).expect("open vault"));
    vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
    let server = Arc::new(
        SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("vault-support-grants-doors".into()),
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
    let owner_person = vault
        .ensure_embedded_owner_actor()
        .expect("the owner's PERSON");
    let support_person = EntityId::now();
    vault
        .put_entity(
            &support_person,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 1, end: 1 },
            1,
            b"our support person",
        )
        .expect("a live support PERSON");
    let app = build_app(server);
    let agent = if pair {
        Some(pair_agent(&vault, &app, &issuer, "support-grants-agent", [0x42; 32]).await)
    } else {
        None
    };
    Served {
        _dir: dir,
        vault,
        app,
        issuer,
        owner_slip,
        owner_token,
        owner_person,
        support_person,
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
) -> Holder {
    let principal = vault.ensure_agent_principal(name).expect("agent principal");
    let key = SigningKey::from_bytes(&seed);
    let binding_key = key.verifying_key().to_bytes();
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
    let signature = hex(&key.sign(&transcript).to_bytes());
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
    Holder { key, slip, token }
}

/// The world a support grant names.
fn support_world() -> ScopeId {
    ScopeId(EntityId::now())
}

/// The bounds the owner selects: one named world, every facet, band and
/// audience, the sensitive ceiling, and the classes `verbs`.
fn support_scope(world: ScopeId, verbs: &[&str]) -> Scope {
    let mut scope = Scope::top();
    scope.worlds = ScopeAxis::Some(BTreeSet::from([world]));
    scope.verbs = ScopeAxis::Some(verbs.iter().map(|verb| (*verb).to_owned()).collect());
    scope.sensitivity = SensitivityCeiling::AtMost(Sensitivity::Sensitive);
    scope
}

impl Served {
    fn agent(&self) -> &Holder {
        self.agent
            .as_ref()
            .expect("a self-hosted fixture pairs an agent")
    }

    /// The request binding `caller` signs afresh for one request.
    fn binding(&self, caller: Caller<'_>) -> String {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = format!("oneiron-request:{timestamp}:{nonce}");
        let held = |holder: &Holder| {
            let transcript = holder
                .slip
                .binding_transcript(challenge.as_bytes())
                .expect("holder binding transcript");
            hex(&holder.key.sign(&transcript).to_bytes())
        };
        let signature = match caller {
            Caller::Owner => hex(&self
                .issuer
                .binding_proof(&self.owner_slip, challenge.as_bytes())
                .expect("owner holder proof")),
            Caller::Agent => held(self.agent()),
            Caller::Support(holder) => held(holder),
        };
        json!({"timestamp": timestamp, "nonce": nonce, "signature": signature}).to_string()
    }

    fn token<'a>(&'a self, caller: Caller<'a>) -> &'a str {
        match caller {
            Caller::Owner => self.owner_token.as_str(),
            Caller::Agent => self.agent().token.as_str(),
            Caller::Support(holder) => holder.token.as_str(),
        }
    }

    /// `caller` posts `verb` with `input` to its facade door: the status and
    /// the body.
    async fn post(&self, caller: Caller<'_>, verb: &str, input: Value) -> (StatusCode, Value) {
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("/v1/core/facade/{verb}"))
            .header("authorization", format!("Bearer {}", self.token(caller)))
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
        let bytes = to_bytes(response.into_body(), 16 * 1024 * 1024)
            .await
            .expect("facade response body");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    /// The mint input for the support PERSON, its key `key`, bounds
    /// `scope` and lifetime `ttl_secs`.
    fn mint_input(&self, key: &SigningKey, scope: &Scope, ttl_secs: u64) -> Value {
        json!({
            "holder": self.support_person.to_hex(),
            "holder_class": "human",
            "holder_key": hex(&key.verifying_key().to_bytes()),
            "scope": serde_json::to_value(scope).expect("scope JSON"),
            "ttl_secs": ttl_secs,
            "purpose": "fix the reminder that never fires",
            "ticket_ref": "SUP-DOORS-CUSTODY",
        })
    }

    /// The owner mints a grant to the support party's key from `seed`:
    /// asserts the 200 and answers the support credential and the answer.
    async fn mint(&self, seed: u8, scope: &Scope, ttl_secs: u64) -> (Holder, Value) {
        let key = SigningKey::from_bytes(&[seed; 32]);
        let (status, minted) = self
            .post(Caller::Owner, MINT, self.mint_input(&key, scope, ttl_secs))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner mints a grant: {minted}");
        let token = minted["slip"]
            .as_str()
            .expect("the mint answers the support credential")
            .to_owned();
        let slip = CapabilitySlip::from_token(&token).expect("the support slip");
        (Holder { key, slip, token }, minted)
    }

    /// The owner's list of every support grant, ended ones included.
    async fn every_grant(&self) -> Vec<Value> {
        let (status, list) = self
            .post(Caller::Owner, LIST, json!({"include_inactive": true}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner lists grants: {list}");
        list["grants"].as_array().expect("a list of grants").clone()
    }

    /// The owner's list of active support grants.
    async fn active_grants(&self) -> Vec<Value> {
        let (status, list) = self.post(Caller::Owner, LIST, json!({})).await;
        assert_eq!(status, StatusCode::OK, "the owner lists grants: {list}");
        list["grants"].as_array().expect("a list of grants").clone()
    }
}

/// The owner mints a grant: the support party's own key holds the slip,
/// the support PERSON is its holder, and its deadline is the lifetime the
/// owner chose; the owner's list shows it active with its one-tap revoke.
/// (P1, P2: a grant to support, time-limited.)
#[test]
fn the_owner_mints_a_time_limited_grant_to_the_support_partys_key() {
    run_on_engine_stack("support-grants-mint", || async {
        let served = served().await;
        let scope = support_scope(support_world(), &["core:read"]);
        let (support, minted) = served.mint(0x51, &scope, 1800).await;

        assert!(
            support.token.starts_with("v2.slip."),
            "the support credential is a slip: {minted}"
        );
        let grant = &minted["grant"];
        assert_eq!(
            support.slip.claims.binding_key,
            support.key.verifying_key().to_bytes(),
            "the slip binds the support party's own key"
        );
        assert_eq!(
            support.slip.claims.holder_ref,
            served.support_person.to_hex(),
            "the slip's holder is the support PERSON"
        );
        assert_eq!(
            grant["grant_ref"],
            hex(&support.slip.claims.slip_id),
            "{minted}"
        );
        assert_eq!(grant["holder"], served.support_person.to_hex(), "{minted}");
        assert_eq!(grant["holder_class"], "human", "{minted}");
        assert_eq!(grant["status"], "active", "{minted}");
        assert_eq!(
            grant["approved_by"],
            served.owner_person.to_hex(),
            "{minted}"
        );
        assert_eq!(grant["revoke_command"], REVOKE, "{minted}");
        let approved_at = grant["approved_at"].as_u64().expect("approved_at");
        let deadline = grant["wall_expires_at"].as_u64().expect("wall_expires_at");
        assert_eq!(
            deadline - approved_at,
            1800,
            "the grant ends the lifetime the owner chose after its approval: {minted}"
        );
        assert!(
            minted["decision_ref"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
            "the mint lands its Gate receipt: {minted}"
        );

        let active = served.active_grants().await;
        assert_eq!(active.len(), 1, "{active:?}");
        assert_eq!(active[0]["grant_ref"], grant["grant_ref"], "{active:?}");
        assert_eq!(active[0]["status"], "active", "{active:?}");
    });
}

/// The support credential reaches exactly its bounds: its ceiling is the
/// grant's one named world and its classes (`read` added), and a write or an
/// export is refused. (P1: inside explicit bounds.)
#[test]
fn a_support_credential_reaches_only_its_bounds() {
    run_on_engine_stack("support-grants-bounds", || async {
        let served = served().await;
        let world = support_world();
        let scope = support_scope(world, &["core:read"]);
        let (support, minted) = served.mint(0x52, &scope, 3600).await;

        let (status, ceiling) = served
            .post(Caller::Support(&support), CEILING, json!({}))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "support reads its ceiling: {ceiling}"
        );
        assert_eq!(ceiling["kind"], "ceiling", "{ceiling}");
        assert_eq!(
            ceiling["scope"]["worlds"],
            serde_json::to_value(ScopeAxis::Some(BTreeSet::from([world]))).expect("worlds JSON"),
            "the credential reaches the one world the owner named: {ceiling}"
        );
        assert_eq!(
            ceiling["scope"]["verbs"],
            serde_json::to_value(ScopeAxis::Some(BTreeSet::from([
                "core:read".to_owned(),
                "read".to_owned(),
            ])))
            .expect("verbs JSON"),
            "the credential carries the selected class and read: {ceiling}"
        );
        assert_eq!(
            minted["grant"]["scope"]["worlds"], ceiling["scope"]["worlds"],
            "the owner reviews the worlds the credential reaches: {minted}"
        );

        let (status, body) = served
            .post(
                Caller::Support(&support),
                "vault.remember",
                json!({
                    "predicate": "support.wrote",
                    "subject_ref": served.owner_person.to_hex(),
                    "value": {"text": "support writes nothing on a read grant"},
                    "confidence": 0.9,
                    "source": "user_stated",
                }),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a read grant writes nothing: {body}"
        );
        let (status, body) = served
            .post(
                Caller::Support(&support),
                "vault.export.scoped",
                json!({"selector": {"kinds": []}, "channel": {
                    "channel_ref": "support-grants-doors",
                    "scope": {
                        "worlds": {"kind": "all"}, "facets": {"kind": "all"},
                        "bands": {"kind": "all"}, "audience": {"kind": "all"},
                        "verbs": {"kind": "all"}, "sensitivity": {"kind": "all"},
                    },
                }}),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "export is never support's: {body}"
        );
    });
}

/// The grant doors are the owner's: the support party on its own grant and
/// a paired agent each get 403 at mint, list and revoke, and the owner's
/// list is unchanged. (Door.)
#[test]
fn the_grant_doors_refuse_support_and_an_agent() {
    run_on_engine_stack("support-grants-owner-doors", || async {
        let served = served().await;
        let scope = support_scope(support_world(), &["core:read"]);
        let (support, minted) = served.mint(0x53, &scope, 3600).await;
        let grant_ref = minted["grant"]["grant_ref"].clone();
        let before = served.every_grant().await;

        for (name, caller) in [
            ("support", Caller::Support(&support)),
            ("agent", Caller::Agent),
        ] {
            let other = SigningKey::from_bytes(&[0x54; 32]);
            let doors = [
                (MINT, served.mint_input(&other, &scope, 3600)),
                (LIST, json!({"include_inactive": true})),
                (REVOKE, json!({"grant_ref": grant_ref})),
            ];
            for (verb, input) in doors {
                let (status, body) = served.post(caller, verb, input).await;
                assert_eq!(status, StatusCode::FORBIDDEN, "{name} at {verb}: {body}");
                assert_eq!(
                    error_code(&body),
                    Some("FORBIDDEN"),
                    "{name} at {verb}: {body}"
                );
            }
        }

        assert_eq!(
            served.every_grant().await,
            before,
            "nothing was minted or revoked"
        );
        let (status, ceiling) = served
            .post(Caller::Support(&support), CEILING, json!({}))
            .await;
        assert_eq!(status, StatusCode::OK, "the grant still stands: {ceiling}");
    });
}

/// A revoke ends the grant at once: the support credential's next call is
/// refused, the owner's list shows it revoked, a repeat changes nothing,
/// and an unknown grant is not found. (P2: revocable.)
#[test]
fn a_revoke_ends_the_grant_at_once() {
    run_on_engine_stack("support-grants-revoke", || async {
        let served = served().await;
        let scope = support_scope(support_world(), &["core:read"]);
        let (support, minted) = served.mint(0x55, &scope, 3600).await;
        let grant_ref = minted["grant"]["grant_ref"].clone();
        let (status, body) = served
            .post(Caller::Support(&support), CEILING, json!({}))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the grant stands before its revoke: {body}"
        );

        let (status, revoked) = served
            .post(Caller::Owner, REVOKE, json!({"grant_ref": grant_ref}))
            .await;
        assert_eq!(status, StatusCode::OK, "the owner revokes: {revoked}");
        assert_eq!(revoked["grant_ref"], grant_ref, "{revoked}");
        assert_eq!(
            revoked["holder"],
            served.support_person.to_hex(),
            "{revoked}"
        );
        assert_eq!(revoked["changed"], true, "{revoked}");
        assert!(revoked["revoked_at"].as_u64().is_some(), "{revoked}");
        assert!(revoked["decision_ref"].as_str().is_some(), "{revoked}");
        assert_eq!(
            revoked["delivered_recallable"], false,
            "what support read is not recalled: {revoked}"
        );

        let (status, body) = served
            .post(Caller::Support(&support), CEILING, json!({}))
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a revoked grant is refused at its next use: {body}"
        );
        assert!(
            served.active_grants().await.is_empty(),
            "no grant is active"
        );
        let every = served.every_grant().await;
        assert_eq!(every.len(), 1, "{every:?}");
        assert_eq!(every[0]["grant_ref"], grant_ref, "{every:?}");
        assert_eq!(every[0]["status"], "revoked", "{every:?}");

        let (status, again) = served
            .post(Caller::Owner, REVOKE, json!({"grant_ref": grant_ref}))
            .await;
        assert_eq!(status, StatusCode::OK, "a repeat revoke answers: {again}");
        assert_eq!(again["changed"], false, "a repeat changes nothing: {again}");
        assert!(again.get("revoked_at").is_none(), "{again}");

        let (status, body) = served
            .post(Caller::Owner, REVOKE, json!({"grant_ref": "00".repeat(32)}))
            .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "an unknown grant: {body}");
    });
}

/// The grant ends at its deadline on the vault's own clock: the support
/// credential is refused once the clock passes it, and the owner's list
/// shows it expired. (P2: time-limited.)
#[test]
fn a_grant_ends_at_its_deadline() {
    run_on_engine_stack("support-grants-deadline", || async {
        let t0 = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("wall clock after the epoch")
            .as_secs();
        let clock = ManualClock::new(t0);
        let mut config = VaultConfig::device();
        config.store_clock = clock.bundle();
        let served = served_with(config, false).await;
        let scope = support_scope(support_world(), &["core:read"]);
        let (support, minted) = served.mint(0x56, &scope, 1).await;
        let deadline = minted["grant"]["wall_expires_at"]
            .as_u64()
            .expect("wall_expires_at");
        let (status, body) = served
            .post(Caller::Support(&support), CEILING, json!({}))
            .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the grant stands before its deadline: {body}"
        );

        clock.set(deadline + 5);
        let (status, body) = served
            .post(Caller::Support(&support), CEILING, json!({}))
            .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a grant past its deadline is refused: {body}"
        );
        let every = served.every_grant().await;
        assert_eq!(every.len(), 1, "{every:?}");
        assert_eq!(every[0]["status"], "expired", "{every:?}");
        assert!(
            served.active_grants().await.is_empty(),
            "no grant is active"
        );
    });
}

/// The mint keeps to its bounds: a lifetime past the longest, an export
/// class, every world, an owner as holder, and a key another credential
/// holds are each refused, and nothing is minted. (P1: explicit bounds.)
#[test]
fn the_mint_refuses_what_its_bounds_exclude() {
    run_on_engine_stack("support-grants-refusals", || async {
        let served = served().await;
        let key = SigningKey::from_bytes(&[0x57; 32]);
        let scope = support_scope(support_world(), &["core:read"]);
        let mut every_world = scope.clone();
        every_world.worlds = ScopeAxis::All;
        let agent_key = served.agent().key.verifying_key().to_bytes();

        let mut cases = vec![
            (
                "a lifetime past the longest",
                served.mint_input(&key, &scope, MAX_TTL_SECS + 1),
            ),
            (
                "an export class",
                served.mint_input(&key, &support_scope(support_world(), &["export"]), 3600),
            ),
            ("every world", served.mint_input(&key, &every_world, 3600)),
        ];
        let mut owner_holder = served.mint_input(&key, &scope, 3600);
        owner_holder["holder"] = json!(served.owner_person.to_hex());
        cases.push(("the owner as holder", owner_holder));
        let mut held_key = served.mint_input(&key, &scope, 3600);
        held_key["holder_key"] = json!(hex(&agent_key));
        cases.push(("a key the paired agent holds", held_key));

        for (case, input) in cases {
            let (status, body) = served.post(Caller::Owner, MINT, input).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: {body}");
            assert_eq!(error_code(&body), Some("BAD_REQUEST"), "{case}: {body}");
        }
        assert!(served.every_grant().await.is_empty(), "nothing was minted");
    });
}

/// On a hosted vault the operator's root acts as nobody: each grant door
/// answers it the typed refusal that asks for a support grant. (P3.)
#[test]
fn a_hosted_operator_root_gets_the_typed_refusal() {
    run_on_engine_stack("support-grants-hosted-root", || async {
        let mut config = VaultConfig::device();
        config.privacy.posture = HostingPrivacyPosture::Hosted;
        let served = served_with(config, false).await;
        let key = SigningKey::from_bytes(&[0x58; 32]);
        let scope = support_scope(support_world(), &["core:read"]);
        let doors = [
            (MINT, served.mint_input(&key, &scope, 3600)),
            (LIST, json!({"include_inactive": true})),
            (REVOKE, json!({"grant_ref": "00".repeat(32)})),
        ];
        for (verb, input) in doors {
            let (status, body) = served.post(Caller::Owner, verb, input).await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "the operator root at {verb}: {body}"
            );
            assert_eq!(
                error_code(&body),
                Some(HOST_ACTION_REFUSED),
                "the operator root at {verb}: {body}"
            );
        }
    });
}
