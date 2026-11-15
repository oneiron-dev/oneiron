#![cfg(oneiron_test_support)]
//! A run's own skill pack load through the served door (FIX
//! [SKILL-HUB-PROMOTION-VERBS], ND-001's pack-load half):
//! `vault.skills.pack.load` on the caller's attached live run. Its grant is
//! the run itself: the live-run guard holds the run and rechecks its lease
//! and attachment, and the load checks that lease again, with the loadable
//! check, in the transaction that stamps the attempt's manifest.
//!
//! Ports the lease half of `admitted_pack_load_returns_actual_files_and_stamps_once`
//! (`crates/oneiron/src/skill_hub/admission_tests.rs`): a skill that is not
//! active refuses and stamps nothing; once active, the run's load answers
//! the pack's exact files and stamps the attempt's manifest once. A handle
//! naming no live run is refused before any load.
//!
//! The run is the seeded default agent's root run, leased and registered
//! live through `oneiron_server::test_doors::live_run_step`; its own agent's
//! credential attaches over `POST /v1/core/live-runs/{run}/attach`, as
//! `tests/run_step_live_run.rs` does.
//!
//! Reads JSON only for the new verb, so on a base without it the test fails
//! at its first load status.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support
//! --no-fail-fast --test skill_pack_load_doors`.

#[path = "support/engine_stack.rs"]
mod engine_stack;

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use engine_stack::on_engine_stack;
use oneiron::agent_def::AgentDefinition;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent, SpendScopeId, agent_dispatch_actor,
};
use oneiron::attempt_queue::{
    AttemptRecord, ClaimAttempt, ClaimOutcome, ManifestEntry, ManifestKind,
};
use oneiron::authority::{CapabilitySlip, MachineRole, holder_proof_challenge};
use oneiron::claim::{ClaimApprovalStatus, ClaimSource};
use oneiron::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use oneiron::federation::{Scope as SlipScope, ScopeAxis};
use oneiron::skill::{SkillLifecycle, SkillRecord, canonical_skill_tree_hash};
use oneiron::skill_hub::{HubFile, HubPackage, SkillCapabilitySurface, SkillPackageFormat};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::{AttemptQueue, EntityId, TimeRange, Vault, VaultConfig, WriteActor};
use oneiron_server::build_app;
use oneiron_server::config::SyncServerConfig;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::live_run_step::register_live_run;
use serde_json::{Value, json};
use tower::ServiceExt;

type TestError = Box<dyn std::error::Error>;
type TestResult<T = ()> = Result<T, TestError>;

/// The model the run executes on; the first load stamps it on the attempt.
const MODEL: &str = "fixture/model@1";
/// The run's budget: roomy enough that no write here meets its cap.
const RUN_UNITS: u64 = 1_000_000;
/// The lease owner the test claims the run's try as, as a pump holds it.
const WORKER: &str = "skill-pack-load-doors";
/// The skill the run loads, and its pack's one file.
const SKILL_ID: &str = "fixture.pack";
const SKILL_MD: &[u8] = b"---\nname: fixture.pack\ndescription: Check a result\nversion: 1\n---\nCheck the result before you report it.\n";

fn at(t: u64) -> TimeRange {
    TimeRange { start: t, end: t }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A served vault, one leased run of the default agent registered live, and
/// its agent's own credential attached.
struct Fixture {
    app: Router,
    vault: Arc<Vault>,
    attempt: AttemptRecord,
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
        let (_owner, _owner_proof) = embedded_owner(&vault)?;
        let root = vault.ensure_host_root_slip(&issuer)?;
        let server = Arc::new(SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("skill-pack-load-doors".into()),
                ..Default::default()
            },
        )?);

        let (attempt, actor, definition, scope) = leased_run(&vault)?;
        let run = EntityId::now();
        register_live_run(
            &server,
            run,
            actor,
            &attempt,
            MODEL,
            definition,
            Some(scope),
        )?;

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
            attempt,
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

    /// `vault.skills.pack.load` of `skill` on the live run `handle` names.
    async fn load_on(&self, handle: &str, skill: EntityId) -> TestResult<(StatusCode, Value)> {
        self.post(
            "/v1/core/facade/vault.skills.pack.load",
            json!({"live_run": handle, "spec": {"skill": skill.to_hex()}}),
        )
        .await
    }

    /// `vault.skills.pack.load` of `skill` on this credential's attached run.
    async fn load(&self, skill: EntityId) -> TestResult<(StatusCode, Value)> {
        self.load_on(&self.handle, skill).await
    }

    /// The run's attempt manifest as stored.
    fn manifest(&self) -> TestResult<Vec<ManifestEntry>> {
        Ok(AttemptQueue::new(&self.vault)
            .get(self.attempt.id)?
            .ok_or("the run's attempt")?
            .manifest)
    }

    /// A shared generated skill, approved and still a Candidate, stored with
    /// its exact one-file package.
    fn candidate_pack(&self) -> TestResult<(EntityId, SkillRecord)> {
        let id = EntityId::now();
        let files = vec![HubFile::new("SKILL.md", SKILL_MD.to_vec())];
        let hash = canonical_skill_tree_hash(
            files
                .iter()
                .map(|file| (file.path.as_str(), file.content.as_slice())),
        )?;
        let record = SkillRecord::new(
            SKILL_ID,
            "Check a result",
            "1",
            ClaimApprovalStatus::Approved,
            SkillLifecycle::Candidate,
            ClaimSource::Generated,
            0.5,
            true,
            false,
            vec![],
            rmpv::Value::Map(vec![(
                rmpv::Value::from("source"),
                rmpv::Value::from("fixture"),
            )]),
        )
        .with_content_hash(hash);
        let mut package = HubPackage::new(record.clone(), files, SkillCapabilitySurface::default());
        package.format = SkillPackageFormat::Native;
        let now = self.vault.now_recorded_at();
        oneiron::test_doors::callable_skill::put_skill_record_and_package(
            &self.vault,
            &id,
            &record,
            &package,
            at(now),
            now,
        )?;
        Ok((id, record))
    }
}

/// The leased try of a root run of the seeded default agent, dispatched with
/// a budget so it spends under a scope of its own: the try, the run's actor,
/// its frozen definition and its scope.
fn leased_run(
    vault: &Vault,
) -> TestResult<(AttemptRecord, WriteActor, AgentDefinition, SpendScopeId)> {
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
    let scope = dispatcher
        .spend_scope_for_attempt(leased.id)?
        .ok_or("the budgeted run spends under a scope")?;
    Ok((leased, actor, status.input.definition, scope))
}

/// Port of the lease half of `admitted_pack_load_returns_actual_files_and_stamps_once`.
#[test]
fn a_runs_pack_load_answers_the_exact_files_and_stamps_its_manifest_once() -> TestResult {
    on_engine_stack(|| async {
        let fixture = Fixture::new().await?;
        let (skill, record) = fixture.candidate_pack()?;
        let before = fixture.manifest()?;
        assert!(
            before.iter().all(|entry| entry.kind != ManifestKind::Skill),
            "no skill loaded yet: {before:?}"
        );

        // Not yet active: the load refuses and stamps nothing.
        let (status, body) = fixture.load(skill).await?;
        assert!(
            status.is_client_error() && body.to_string().contains("active approved"),
            "a candidate does not load: {status} {body}"
        );
        assert_eq!(fixture.manifest()?.len(), before.len(), "nothing stamped");

        let mut active = record;
        active.lifecycle_status = SkillLifecycle::Active;
        let now = fixture.vault.now_recorded_at();
        fixture
            .vault
            .update_skill_record(&skill, &active, at(now), now)?;

        // A handle naming no live run lends no lease: refused before any load.
        let (status, body) = fixture
            .load_on(
                "lr1.11111111111111111111111111111111.22222222222222222222222222222222",
                skill,
            )
            .await?;
        assert_eq!(
            (status, body["error"]["code"].as_str()),
            (StatusCode::FORBIDDEN, Some("live_run_unavailable")),
            "{body}"
        );
        assert_eq!(fixture.manifest()?.len(), before.len(), "nothing stamped");

        // The run's own load: the exact files, stamped once.
        let (status, loaded) = fixture.load(skill).await?;
        assert_eq!(status, StatusCode::OK, "the active skill loads: {loaded}");
        assert_eq!(loaded["entity"], skill.to_hex().as_str(), "{loaded}");
        assert_eq!(loaded["skill_id"], SKILL_ID, "{loaded}");
        assert_eq!(loaded["version"], "1", "{loaded}");
        assert_eq!(
            loaded["files"],
            json!([{"path": "SKILL.md", "content": SKILL_MD}]),
            "the pack's exact files"
        );
        let after = fixture.manifest()?;
        assert_eq!(after.len(), before.len() + 1, "one stamp: {after:?}");
        let stamp = after.last().ok_or("the load's stamp")?;
        assert_eq!(stamp.kind, ManifestKind::Skill);
        assert_eq!(stamp.reference, SKILL_ID);
        assert_eq!(stamp.version, "1");
        assert_eq!(
            fixture
                .vault
                .get_skill_record(&skill)?
                .ok_or("the skill")?
                .lifecycle_status,
            SkillLifecycle::Active
        );
        Ok(())
    })
}
