#![cfg(oneiron_test_support)]
//! Public-door promise tests for the `self.secrets` family (ruling L4-23 =
//! A: each test proves a promise at the door; DOOR-FAMILIES Part 2, row 2).
//!
//! Every case drives the real route `POST /v1/core/facade/self.secrets.<verb>`
//! in process (`build_app` + `oneshot`) as a run's own agent: the seeded
//! default agent's root run, dispatched and leased, registered live through
//! `oneiron_server::test_doors::live_run_step` as the pump's entry does, and
//! attached by the agent's own credential over
//! `POST /v1/core/live-runs/{run}/attach`. The owner registers and rotates
//! the secret through the engine's owner doors, the only path that answers
//! the secret's handle. Each case owns its vault. No sockets, no sleeps, no
//! models, and no provider send: every use asserted here is refused before
//! its send.
//!
//! The grants are door grants (rung T0, operation `slack.auth_test`). The
//! promises, with their canon lines (oneiron-docs `generated/`,
//! `oneiron/gate/oneiron-arch-0069-secret-custody-v1.md`):
//! - a grant ends at teardown: `:98` "injected at materialization, revoked
//!   at teardown", so neither a renew nor a use revives a torn-down grant;
//! - after a rotation the next grant takes the new value: `:372` "the next
//!   lease materializes the new value", so a fresh materialize and a renew
//!   both pin the new generation;
//! - rotation is lease-scoped: `:443` "Rotation is lease-scoped.", so a
//!   grant minted before the rotation refuses its use as stale until it is
//!   renewed (the `self.secrets.use` row: "a grant minted before a rotation
//!   refuses until renewed");
//! - a grant is stamped on the vault's own clock (NO-DOOR ND-095, the door
//!   half of `secret_lease::tests::the_typed_instant_path_stamps_from_the_vault_clock_and_honours_its_bound`):
//!   its expiry is its stamp plus the ttl, clamped to 1..=3600 s, and the
//!   caller names no instant and no tier.
//!
//! Every answer is metadata and never carries the value or its base64
//! (`verbs/secret_grant.rs`: "Every answer here is metadata").
//!
//! These promises hold on main. Their red proof is a seeded fault (Test rules
//! v2, rule 5), named in the PR.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! self_secrets_doors`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpendScopeId, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{CapabilitySlip, MachineRole, holder_proof_challenge};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope as SlipScope, ScopeAxis};
use oneiron::secret_custody::{OwnerSecretRegistration, RequestedBinding};
use oneiron::secret_record::{CustodyClass, CustodyTier};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{AttemptQueue, EntityId, Vault, VaultConfig};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::live_run_step::register_live_run;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The model the live run names; nothing on these doors reads it.
const MODEL: &str = "paid/step-model@r1";
/// The lease owner the test claims the run's try as, as a pump holds it.
const WORKER: &str = "self-secrets-doors";
/// The slip id of the agent's own credential, apart from the root's.
const AGENT_SLIP: [u8; 32] = [0x5d; 32];
/// The secret's custody name.
const NAME: &str = "self-secrets-doors-token";
/// The table operation every grant is for, and the effector it binds.
const OPERATION: &str = "slack.auth_test";
const EFFECTOR: &str = "connector:slack";
/// The value the owner registers, and the one a rotation replaces it with.
const FIRST: &[u8] = b"self_secrets_doors_first_value";
const ROTATED: &[u8] = b"self_secrets_doors_rotated_value";
/// The engine's default and largest grant ttl, in seconds.
const DEFAULT_TTL: u64 = 900;
const MAX_TTL: u64 = 3600;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after 1970")
        .as_secs()
}

fn error_code(body: &Value) -> Option<&str> {
    body["error"]["code"].as_str()
}

/// Neither secret value nor its base64 appears anywhere in `body`.
fn assert_value_free(what: &str, body: &Value) {
    let text = body.to_string();
    for value in [FIRST, ROTATED] {
        let raw = String::from_utf8_lossy(value);
        assert!(
            !text.contains(&*raw),
            "{what} carries a secret value: {text}"
        );
        assert!(
            !text.contains(&STANDARD.encode(value)),
            "{what} carries a secret value's base64: {text}"
        );
    }
}

/// A served vault, one leased run of the default agent registered live,
/// its agent's own credential attached, and one secret the owner bound to
/// the operation's effector at rung T0.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    slip: CapabilitySlip,
    holder: SigningKey,
    live_run: String,
    secret: String,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let dir = tempfile::tempdir()?;
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
        vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
        let issuer = oneiron::test_support::provision_engine_machines(&vault);
        vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
        let (_owner, owner) = embedded_owner(&vault)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("self-secrets-doors".into()),
                ..Default::default()
            },
        )?);

        let (leased, actor, definition, scope) = leased_run(&vault)?;
        let run = EntityId::now();
        register_live_run(&server, run, actor, &leased, MODEL, definition, Some(scope))?;

        let registered = vault.register_private_copy_as_owner(
            &owner,
            &OwnerSecretRegistration {
                name: NAME,
                class: CustodyClass::CustodyPortable,
                device_only: false,
                rung: CustodyTier::T0Doored,
                bindings: vec![RequestedBinding {
                    effector: EFFECTOR.to_owned(),
                    tier_ceiling: None,
                    scopes: vec!["read".to_owned()],
                }],
                manifest: None,
                value: FIRST,
            },
            unix_now(),
        )?;

        // The run's own agent, on a credential of its own that reads and
        // writes, as `token agent` pairs one.
        let holder = SigningKey::from_bytes(&[0x5c; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = AGENT_SLIP;
        claims.holder_ref = actor.entity_ref().to_hex();
        claims.binding_key = holder.verifying_key().to_bytes();
        claims.actor_class = Some("agent".to_owned());
        claims.scope = SlipScope::top();
        claims.scope.verbs = ScopeAxis::Some(BTreeSet::from([
            "core:read".to_owned(),
            "core:write".to_owned(),
        ]));
        let slip = vault.mint_capability_slip(&issuer, claims)?;

        let mut fixture = Self {
            app: build_app(server),
            vault,
            owner,
            slip,
            holder,
            live_run: String::new(),
            secret: registered.handle,
            _dir: dir,
        };
        let (status, body) = fixture
            .post(
                &format!("/v1/core/live-runs/{}/attach", run.to_hex()),
                json!({}),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "the run's agent attaches: {body}");
        fixture.live_run = body["liveRun"]
            .as_str()
            .ok_or("the attach answers a handle")?
            .to_owned();
        Ok(fixture)
    }

    /// A request signed by the agent's own holder key.
    async fn post(&self, path: &str, body: Value) -> TestResult<(StatusCode, Value)> {
        let timestamp = self.vault.now_recorded_at();
        let nonce = EntityId::now().to_hex();
        let challenge = holder_proof_challenge(timestamp, &nonce);
        let signature = self
            .holder
            .sign(&self.slip.binding_transcript(&challenge)?)
            .to_bytes();
        let binding = json!({
            "timestamp": timestamp,
            "nonce": nonce,
            "signature": hex(&signature),
        });
        let request = Request::post(path)
            .header("authorization", format!("Bearer {}", self.slip.to_token()?))
            .header("x-oneiron-binding", binding.to_string())
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        let response = self.app.clone().oneshot(request).await?;
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await?;
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        Ok((status, body))
    }

    /// The agent posts `spec` to `self.secrets.<verb>` on its live run.
    /// Every answer, granted or refused, is value-free.
    async fn verb(&self, verb: &str, spec: Value) -> TestResult<(StatusCode, Value)> {
        let (status, body) = self
            .post(
                &format!("/v1/core/facade/self.secrets.{verb}"),
                json!({"live_run": self.live_run, "spec": spec}),
            )
            .await?;
        assert_value_free(&format!("self.secrets.{verb}"), &body);
        Ok((status, body))
    }

    /// The materialize spec for the operation's door grant over the secret.
    fn grant_spec(&self) -> Value {
        json!({
            "handle": self.secret,
            "purpose": {"kind": "operation", "name": OPERATION},
        })
    }

    /// A door grant materialized for the operation: asserts the 200 and
    /// answers the grant view.
    async fn materialize(&self) -> TestResult<Value> {
        let (status, view) = self.verb("materialize", self.grant_spec()).await?;
        assert_eq!(status, StatusCode::OK, "the agent materializes: {view}");
        assert_eq!(
            (view["tier"].as_u64(), view["status"].as_str()),
            (Some(0), Some("active")),
            "a door grant at rung T0, active: {view}"
        );
        Ok(view)
    }

    async fn renew(&self, grant: &str) -> TestResult<(StatusCode, Value)> {
        self.verb("renew", json!({"grant": grant})).await
    }

    async fn teardown(&self, grant: &str) -> TestResult<(StatusCode, Value)> {
        self.verb("teardown", json!({"grant": grant})).await
    }

    async fn use_grant(&self, grant: &str) -> TestResult<(StatusCode, Value)> {
        self.verb(
            "use",
            json!({"grant": grant, "operation": OPERATION, "arguments": {}}),
        )
        .await
    }

    /// The owner rotates the secret to [`ROTATED`]: the generation it moved
    /// to.
    fn rotate(&self) -> TestResult<u32> {
        let receipt = self
            .vault
            .rotate_secret_as_owner(&self.owner, NAME, ROTATED, unix_now())?;
        Ok(receipt.to_generation)
    }
}

/// The leased try of a root run of the seeded default agent, dispatched
/// with a budget so it spends under a scope of its own: the try, the run's
/// actor, its frozen definition and its scope.
fn leased_run(
    vault: &Vault,
) -> TestResult<(
    AttemptRecord,
    oneiron::WriteActor,
    oneiron::agent_def::AgentDefinition,
    SpendScopeId,
)> {
    let (agent, _) = vault
        .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)?
        .ok_or("the default agent is seeded")?;
    let dispatcher = AgentDispatcher::new(vault);
    let AgentDispatchOutcome::Dispatched(status) = dispatcher.dispatch_with_context(
        DispatchAgent {
            target: AgentDispatchTarget::Custom(agent),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some(WORKER.to_owned()),
            now: 1,
        },
        AgentSpawnContext::default()
            .with_depth_remaining(1)
            .with_budget(1_000_000),
    )?
    else {
        return Err("expected one fresh root run".into());
    };
    let actor = agent_dispatch_actor(&status.input)?;
    let queue = AttemptQueue::new(vault);
    let mut leased = None;
    for _ in 0..64 {
        let ClaimOutcome::Claimed(row) = queue.claim_kind(
            DREAMER_RUNNER_ATTEMPT_KIND,
            ClaimAttempt {
                lease_owner: WORKER.to_owned(),
                now: u64::MAX,
            },
        )?
        else {
            break;
        };
        if row.id == status.attempt.id {
            leased = queue.get(row.id)?;
            break;
        }
    }
    let leased = leased.ok_or("the run's try is ready to claim")?;
    let scope = dispatcher
        .spend_scope_for_attempt(leased.id)?
        .ok_or("the budgeted run spends under a scope")?;
    Ok((leased, actor, status.input.definition, scope))
}

/// The grant's id, as its view names it.
fn grant_id(view: &Value) -> String {
    view["grant"]
        .as_str()
        .expect("a grant view names its grant")
        .to_owned()
}

/// A teardown ends the grant (arch-0069:98, "revoked at teardown"): it
/// answers 200 with the grant revoked, and afterwards a renew and a use of
/// it are each refused 409 `INVALID_STATE` before anything is minted or
/// sent. A second teardown answers 200, still revoked. Red with the seeded
/// fault that lets a retired grant pass as live.
#[test]
fn a_teardown_ends_the_grant_and_no_renew_or_use_revives_it() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let minted = fixture.materialize().await?;
        assert_eq!(
            minted["generation"].as_u64(),
            Some(0),
            "a first grant pins generation 0: {minted}"
        );
        let grant = grant_id(&minted);

        let (status, torn) = fixture.teardown(&grant).await?;
        assert_eq!(status, StatusCode::OK, "the agent tears down: {torn}");
        assert_eq!(
            (torn["grant"].as_str(), torn["status"].as_str()),
            (Some(grant.as_str()), Some("revoked")),
            "the torn-down grant reads revoked: {torn}"
        );

        // The renew first: under a fault that let the grant pass as live,
        // it fails here before any use could reach the provider.
        let (status, renewed) = fixture.renew(&grant).await?;
        assert_eq!(
            (status, error_code(&renewed)),
            (StatusCode::CONFLICT, Some("INVALID_STATE")),
            "a torn-down grant does not renew: {renewed}"
        );
        let (status, used) = fixture.use_grant(&grant).await?;
        assert_eq!(
            (status, error_code(&used)),
            (StatusCode::CONFLICT, Some("INVALID_STATE")),
            "a torn-down grant is not used: {used}"
        );

        let (status, again) = fixture.teardown(&grant).await?;
        assert_eq!(
            (status, again["status"].as_str()),
            (StatusCode::OK, Some("revoked")),
            "a second teardown answers the revoked grant: {again}"
        );
        Ok(())
    })
}

/// After the owner rotates the secret, the next grant takes the new value
/// (arch-0069:372, "the next lease materializes the new value"): a fresh
/// materialize and a renew of the grant from before the rotation each
/// answer a new grant pinned at generation 1, and the renewed grant, now
/// replaced, does not renew a second time.
#[test]
fn the_next_grant_after_a_rotation_pins_the_new_generation() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let before = fixture.materialize().await?;
        let old = grant_id(&before);
        assert_eq!(before["generation"].as_u64(), Some(0), "{before}");

        assert_eq!(fixture.rotate()?, 1, "the owner's rotation moves to 1");

        let fresh = fixture.materialize().await?;
        assert_eq!(
            fresh["generation"].as_u64(),
            Some(1),
            "a grant minted after the rotation pins the new generation: {fresh}"
        );
        assert_ne!(grant_id(&fresh), old, "{fresh}");

        let (status, renewed) = fixture.renew(&old).await?;
        assert_eq!(status, StatusCode::OK, "the agent renews: {renewed}");
        assert_eq!(
            (renewed["generation"].as_u64(), renewed["status"].as_str()),
            (Some(1), Some("active")),
            "a renewal mints at the secret's current generation: {renewed}"
        );
        let successor = grant_id(&renewed);
        assert!(
            successor != old && successor != grant_id(&fresh),
            "a renewal answers a new grant: {renewed}"
        );

        let (status, twice) = fixture.renew(&old).await?;
        assert_eq!(
            (status, error_code(&twice)),
            (StatusCode::CONFLICT, Some("INVALID_STATE")),
            "a replaced grant does not renew again: {twice}"
        );
        Ok(())
    })
}

/// Rotation is lease-scoped (arch-0069:443): a grant minted before the
/// owner's rotation still reads active, but its use is refused 409
/// `INVALID_STATE` as stale, with the renew hint, before anything is sent.
/// Its renewal pins the new generation. Red with the seeded fault that
/// drops the stale check.
#[test]
fn a_grant_from_before_a_rotation_refuses_its_use_until_renewed() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let before = fixture.materialize().await?;
        let old = grant_id(&before);

        assert_eq!(fixture.rotate()?, 1, "the owner's rotation moves to 1");

        let (status, used) = fixture.use_grant(&old).await?;
        assert_eq!(
            (status, error_code(&used)),
            (StatusCode::CONFLICT, Some("INVALID_STATE")),
            "a grant from before the rotation is refused as stale: {used}"
        );
        assert!(
            used["error"]["suggestions"]
                .to_string()
                .contains("Renew the grant"),
            "the stale refusal says to renew: {used}"
        );

        let (status, renewed) = fixture.renew(&old).await?;
        assert_eq!(
            (status, renewed["generation"].as_u64()),
            (StatusCode::OK, Some(1)),
            "the stale grant's renewal pins the new generation: {renewed}"
        );
        Ok(())
    })
}

/// A grant is stamped on the vault's own clock (NO-DOOR ND-095, door half):
/// its stamp is at or past the vault's clock reading before the call and
/// never runs back, and its expiry is the stamp plus the ttl, the default 900 s when none is
/// asked and clamped to 1..=3600 s otherwise. A spec that names an instant
/// or a tier is refused with a client error. Red with the seeded fault that
/// drops the ttl's upper clamp.
#[test]
fn a_grant_is_stamped_on_the_vault_clock_with_its_ttl_clamped() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let mut stamped = 0;
        for (ttl, lifetime) in [
            (None, DEFAULT_TTL),
            (Some(60), 60),
            (Some(0), 1),
            (Some(1_000_000), MAX_TTL),
        ] {
            let mut spec = fixture.grant_spec();
            if let Some(ttl) = ttl {
                spec["ttl_secs"] = json!(ttl);
            }
            let earliest = fixture.vault.now_recorded_at();
            let (status, view) = fixture.verb("materialize", spec).await?;
            assert_eq!(status, StatusCode::OK, "ttl {ttl:?}: {view}");
            let granted = view["granted_at"].as_u64().expect("a granted_at");
            let expires = view["expires_at"].as_u64().expect("an expires_at");
            assert!(
                granted >= earliest.max(stamped),
                "ttl {ttl:?}: the stamp {granted} is the vault's clock, at or past \
                 its reading {earliest} and the last stamp {stamped}: {view}"
            );
            stamped = granted;
            assert_eq!(
                expires - granted,
                lifetime,
                "ttl {ttl:?}: the expiry is the stamp plus the clamped ttl: {view}"
            );
        }

        for (field, value) in [
            ("granted_at", json!(1)),
            ("expires_at", json!(u64::MAX)),
            ("tier", json!(2)),
        ] {
            let mut spec = fixture.grant_spec();
            spec[field] = value;
            let (status, body) = fixture.verb("materialize", spec).await?;
            assert!(
                status.is_client_error(),
                "a spec naming {field} is refused: {status} {body}"
            );
        }
        Ok(())
    })
}
