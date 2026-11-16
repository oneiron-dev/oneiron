#![cfg(oneiron_test_support)]
//! BROWSER-REFUSAL-STATUS-GAP: a typed browser refusal on an agent's attached
//! live run answers at its facade door with its own status, never as this
//! server's failure (500).
//!
//! The run is the seeded default agent's root run, dispatched with a budget
//! and leased; `oneiron_server::test_doors::live_run_step` registers it as
//! the pump's entry does, and the agent's own credential attaches over
//! `POST /v1/core/live-runs/{run}/attach` (the fixture of
//! `run_step_live_run.rs`). The server binds no browser guest, so no browser
//! starts: each call is refused at the run guest's admission, which is the
//! same door body (`on_browser`) and the same translator
//! (`browser_refusal_status`) every typed browser refusal meets.
//! - A vault whose browser connector pack is not installed answers
//!   `browser_pack_not_installed` as 409: the owner's setup changes it.
//! - Once the owner installs the pack and its guest connection is checked,
//!   a host that binds no browser guest answers `browser_unbound` as 503:
//!   this host serves the run no browser now.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p
//! oneiron-server --all-features --features oneiron/test-support --test
//! browser_refusal_status`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, agent_dispatch_actor,
};
use oneiron::attempt_queue::{AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::authority::{CapabilitySlip, MachineRole, holder_proof_challenge};
use oneiron::connector_key::{PackConnectionCheck, PackConnectionEvidence, PackConnectionVerifier};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope as SlipScope, ScopeAxis};
use oneiron::skill_hub::pack_catalog::{PackInstallStatus, PackSetupAnswer};
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

/// The model the registered run executes on; no call reaches it.
const MODEL: &str = "fixture/browser-refusal@r1";
/// The run's budget.
const RUN_UNITS: u64 = 1_000_000;
/// The lease owner the test claims the run's try as, as a pump holds it.
const WORKER: &str = "browser-refusal-status";
/// The browser's built-in connector pack, its channel and its guest
/// connection (`packs/builtin/browser/PACK.md`).
const BROWSER_PACK: &str = "oneiron.browser";
const BROWSER_CHANNEL: &str = "browser";
const GUEST_CONNECTION: &str = "browser-guest";
/// The offline check's evidence: a fixed 32-byte digest in hex, as a
/// provider reply's digest is written; a local guest sends no reply.
const GUEST_CHECK_EVIDENCE: &str =
    "6c6f63616c2d67756573742d636865636b2d6f66666c696e652d666978747572";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The host's `browser.session` check, offline: the guest connection is
/// local, so its evidence names this host's guest and no provider scope.
/// Installation, permission grants and qualification still run through the
/// engine's own setup doors.
struct LocalGuestCheck;

impl PackConnectionVerifier for LocalGuestCheck {
    fn verify(
        &self,
        _vault: &Vault,
        check: &PackConnectionCheck<'_>,
    ) -> Result<PackConnectionEvidence, String> {
        assert_eq!(check.pack, BROWSER_PACK);
        assert_eq!(check.connection, GUEST_CONNECTION);
        Ok(PackConnectionEvidence {
            account: "browser guest on this host".into(),
            provider_account: None,
            scopes: Vec::new(),
            evidence: GUEST_CHECK_EVIDENCE.into(),
        })
    }
}

/// A served vault, one leased run of the default agent registered live, and
/// its agent's own credential attached. The server binds no browser guest.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    owner: AuthenticatedOwner,
    slip: CapabilitySlip,
    holder: SigningKey,
    handle: String,
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
                auth_secret: Some("browser-refusal-status".into()),
                ..Default::default()
            },
        )?);

        let (leased, actor, definition) = leased_run(&vault)?;
        let run = EntityId::now();
        register_live_run(&server, run, actor, &leased, MODEL, definition, None)?;

        // The run's own agent, on a credential of its own that reads and
        // writes, as `token agent` pairs one.
        let holder = SigningKey::from_bytes(&[0x6b; 32]);
        let mut claims = root.claims.clone();
        claims.parent_id = None;
        claims.slip_id = [0x6a; 32];
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
            handle: String::new(),
            _dir: dir,
        };
        let (status, body) = fixture
            .post(
                &format!("/v1/core/live-runs/{}/attach", run.to_hex()),
                json!({}),
            )
            .await?;
        assert_eq!(status, StatusCode::OK, "the run's agent attaches: {body}");
        fixture.handle = body["liveRun"]
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

    /// `self.browser.open` on the attached run.
    async fn open(&self) -> TestResult<(StatusCode, Value)> {
        self.post(
            "/v1/core/facade/self.browser.open",
            json!({"live_run": self.handle, "spec": {"url": "https://example.com/"}}),
        )
        .await
    }

    /// The owner installs the browser's connector pack, allows its guest
    /// connection's permission and checks the connection, through the
    /// owner's setup doors: the pack is then Active.
    fn install_browser_pack(&self) -> TestResult {
        let setup = self
            .vault
            .prepare_pack_setup(&self.owner, BROWSER_PACK, None)?;
        self.vault.answer_pack_setup(
            &self.owner,
            BROWSER_PACK,
            Some(&setup.content_hash),
            &PackSetupAnswer::Allow {
                connection: GUEST_CONNECTION.into(),
                permissions: vec!["browse".into()],
            },
        )?;
        let checked = self.vault.verify_pack_connection(
            &self.owner,
            BROWSER_PACK,
            Some(&setup.content_hash),
            GUEST_CONNECTION,
            &LocalGuestCheck,
        )?;
        assert!(checked.ready, "the browser pack's setup is ready");
        assert_eq!(checked.status, PackInstallStatus::Active);
        self.vault.require_builtin_channel_pack(BROWSER_CHANNEL)?;
        Ok(())
    }
}

/// The leased try of a root run of the seeded default agent, dispatched
/// with a budget: the try, the run's actor and its frozen definition.
fn leased_run(
    vault: &Vault,
) -> TestResult<(
    AttemptRecord,
    oneiron::WriteActor,
    oneiron::agent_def::AgentDefinition,
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
            .with_budget(RUN_UNITS),
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
    Ok((leased, actor, status.input.definition))
}

/// The refusal's `error.code`.
fn code(body: &Value) -> &str {
    body["error"]["code"].as_str().unwrap_or("")
}

/// A browser call on a vault whose browser pack is not installed: 409, the
/// owner's setup changes it, never this server's failure.
#[test]
fn a_browser_call_before_the_pack_is_installed_answers_conflict() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (status, body) = fixture.open().await?;
        assert_eq!(
            code(&body),
            "browser_pack_not_installed",
            "the run guest's admission refuses before any browser starts: {status} {body}"
        );
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "an uninstalled browser pack is the vault's setup, not this server's failure: {body}"
        );
        Ok(())
    })
}

/// A browser call once the pack is installed and checked, on a host that
/// binds no browser guest: 503, this host serves the run no browser now.
#[test]
fn a_browser_call_on_a_host_with_no_browser_guest_answers_unavailable() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        fixture.install_browser_pack()?;
        let (status, body) = fixture.open().await?;
        assert_eq!(
            code(&body),
            "browser_unbound",
            "an installed, checked pack meets the host's missing guest: {status} {body}"
        );
        assert_eq!(
            status,
            StatusCode::SERVICE_UNAVAILABLE,
            "a host with no browser guest is unavailable, not failing: {body}"
        );
        Ok(())
    })
}
