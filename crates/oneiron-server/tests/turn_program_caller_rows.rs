#![cfg(oneiron_test_support)]
//! [RSI-PROJECT-WORKFLOW] T5 `each_stage_keeps_its_own_grant`: a turn
//! program's run door serves its own agent exactly five more host-door rows
//! (`vault.arms.admit`, `.forecast`, `.get`, `.units.reserve`, and
//! `vault.gpu.jobs.status`), each under that agent's own Grant, read at each
//! call; no owner fallback.
//!
//! - With a Grant listing the verb, `vault.arms.get` and
//!   `vault.gpu.jobs.status` reach the row's act: an unknown arm or job
//!   answers `not_found`, never `forbidden`.
//! - With no Grant listing it, the same call is refused `forbidden`.
//! - After the owner revokes that Grant, the next call is refused
//!   `forbidden`: nothing was cached at an earlier call.
//! - A row outside the five (`vault.gpu.jobs.list`) stays refused on the
//!   program's door though the Grant lists it, and a pumped run's door
//!   (no program) serves none of the five.
//!
//! On the base the program's door serves none of the five (each answers the
//! host-only refusal `model_unavailable`), so the reach and revocation tests
//! fail there.
//!
//! Run with: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --test turn_program_caller_rows`.

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;

use oneiron::authority::{ActSurface, MachineRole};
use oneiron::code_run::{AgentVerbAnswer, AgentVerbRefusal};
use oneiron::consent::AuthenticatedOwner;
use oneiron::federation::{Scope, ScopeAxis};
use oneiron::memory::{
    MEMORY_CODE_FORBIDDEN, MEMORY_CODE_MODEL_UNAVAILABLE, MEMORY_CODE_NOT_FOUND,
};
use oneiron::test_doors::label_writers::embedded_owner;
use oneiron::verbs::{
    AgentGrantMintRequest, AgentGrantRevokeRequest, mint_agent_grant_as, revoke_agent_grant_as,
};
use oneiron::{EntityId, Vault, VaultConfig};
use oneiron_server::ENGINE_THREAD_STACK_BYTES;
use oneiron_server::server::SyncServer;
use oneiron_server::test_doors::build_server::build_served_server;
use oneiron_server::test_doors::run_program_caller_rows::run_door_call;
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
type DoorAnswer = Result<AgentVerbAnswer, AgentVerbRefusal>;

const ARMS_GET: &str = "vault.arms.get";
const JOBS_STATUS: &str = "vault.gpu.jobs.status";
const JOBS_LIST: &str = "vault.gpu.jobs.list";

/// Runs `test` on a multi-thread runtime whose threads have the engine's
/// stack, driven from a thread that has it too, as the server's binary runs.
fn on_engine_stack<F, Fut>(test: F) -> TestResult
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = TestResult>,
{
    let driver = std::thread::Builder::new()
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || -> Result<(), String> {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .map_err(|error| error.to_string())?
                .block_on(test())
                .map_err(|error| error.to_string())
        })?;
    match driver.join() {
        Ok(outcome) => Ok(outcome?),
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

/// A rooted vault with its embedded owner, served with the default
/// `[serve]` settings.
struct Served {
    _dir: tempfile::TempDir,
    vault: Arc<Vault>,
    server: Arc<SyncServer>,
    owner_proof: AuthenticatedOwner,
}

async fn served() -> TestResult<Served> {
    let dir = tempfile::tempdir()?;
    let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device())?);
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    let issuer = oneiron::test_support::provision_engine_machines(&vault);
    vault.ensure_serving_install_profile(&issuer, MachineRole::Unanswered)?;
    let (_, owner_proof) = embedded_owner(&vault)?;
    vault.ensure_host_root_slip(&issuer)?;
    let server = build_served_server(
        Arc::clone(&vault),
        dir.path(),
        Some("turn-program-caller-rows".into()),
    )
    .await?;
    Ok(Served {
        _dir: dir,
        vault,
        server: Arc::new(server),
        owner_proof,
    })
}

impl Served {
    /// The owner's Grant naming `agent` and listing `verbs` (with `read`,
    /// which a Grant needs to confer). Answers the Grant's row.
    fn mint(&self, agent: EntityId, verbs: &[&str]) -> EntityId {
        let mut authority_scope = Scope::top();
        authority_scope.verbs = ScopeAxis::Some(
            std::iter::once("read")
                .chain(verbs.iter().copied())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
        );
        let minted = mint_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantMintRequest {
                agent,
                authority_scope,
                expires_at: None,
                repo_bounds: None,
                verb_classes: BTreeSet::new(),
                wallet_ref: None,
                working_view_bounds: None,
                check_in_ref: None,
            },
        )
        .unwrap_or_else(|error| panic!("the owner mints {agent:?} a Grant: {error:?}"));
        assert!(
            minted.grant.confers,
            "agent={agent:?} verbs={verbs:?}: the Grant confers; seen {minted:?}"
        );
        minted.grant.grant_ref
    }

    fn revoke(&self, grant: EntityId) {
        revoke_agent_grant_as(
            &self.vault,
            &self.owner_proof,
            ActSurface::ThisInstall,
            AgentGrantRevokeRequest {
                grant_ref: grant,
                seen: None,
            },
        )
        .unwrap_or_else(|error| panic!("the owner revokes Grant {grant:?}: {error:?}"));
    }

    /// `verb` with `input` called by `agent` on a run door: a turn
    /// program's when `program`, else a pumped run's. Off the runtime's
    /// threads, as a run's entry calls it.
    async fn call(&self, agent: EntityId, program: bool, verb: &str, input: Value) -> DoorAnswer {
        let server = Arc::clone(&self.server);
        let runtime = tokio::runtime::Handle::current();
        let verb = verb.to_owned();
        tokio::task::spawn_blocking(move || {
            run_door_call(&server, agent, runtime, program, &verb, input)
        })
        .await
        .expect("the door call's thread joins")
        .unwrap_or_else(|error| panic!("the door answers: {error:?}"))
    }
}

fn unknown_arm() -> Value {
    json!({ "arm": EntityId::now().to_hex() })
}

fn unknown_job() -> Value {
    json!({ "job": EntityId::now().to_hex() })
}

fn refused_as(answer: &DoorAnswer, code: &str, case: &str) {
    match answer {
        Err(refusal) => assert_eq!(
            refusal.code, code,
            "{case}: expected the refusal {code}; seen {refusal:?}"
        ),
        Ok(answer) => panic!("{case}: expected the refusal {code}; seen the answer {answer:?}"),
    }
}

/// The two read rows reach their acts under the agent's Grant, and are
/// refused `forbidden` without one.
#[test]
fn a_program_reaches_the_rows_under_its_own_grant() -> TestResult {
    on_engine_stack(|| async {
        let served = served().await?;
        let granted = EntityId::now();
        served.mint(granted, &[ARMS_GET, JOBS_STATUS]);
        refused_as(
            &served.call(granted, true, ARMS_GET, unknown_arm()).await,
            MEMORY_CODE_NOT_FOUND,
            "actor=granted agent, door=program, verb=vault.arms.get, arm unknown",
        );
        refused_as(
            &served.call(granted, true, JOBS_STATUS, unknown_job()).await,
            MEMORY_CODE_NOT_FOUND,
            "actor=granted agent, door=program, verb=vault.gpu.jobs.status, job unknown",
        );
        let ungranted = EntityId::now();
        refused_as(
            &served.call(ungranted, true, ARMS_GET, unknown_arm()).await,
            MEMORY_CODE_FORBIDDEN,
            "actor=agent with no Grant, door=program, verb=vault.arms.get",
        );
        refused_as(
            &served
                .call(ungranted, true, JOBS_STATUS, unknown_job())
                .await,
            MEMORY_CODE_FORBIDDEN,
            "actor=agent with no Grant, door=program, verb=vault.gpu.jobs.status",
        );
        Ok(())
    })
}

/// The Grant is read at each call: once the owner revokes it, the next
/// call of the same row is refused `forbidden`.
#[test]
fn a_revoked_grant_refuses_the_next_stage() -> TestResult {
    on_engine_stack(|| async {
        let served = served().await?;
        let agent = EntityId::now();
        let grant = served.mint(agent, &[ARMS_GET]);
        refused_as(
            &served.call(agent, true, ARMS_GET, unknown_arm()).await,
            MEMORY_CODE_NOT_FOUND,
            "before the revoke: the granted agent reaches the act",
        );
        served.revoke(grant);
        refused_as(
            &served.call(agent, true, ARMS_GET, unknown_arm()).await,
            MEMORY_CODE_FORBIDDEN,
            "after the revoke: the next stage is refused",
        );
        Ok(())
    })
}

/// Only the five: a host-door row outside them stays refused on the
/// program's door though the Grant lists it, and a pumped run's door
/// serves none of the five.
#[test]
fn only_the_five_rows_open_and_only_on_a_program_door() -> TestResult {
    on_engine_stack(|| async {
        let served = served().await?;
        let agent = EntityId::now();
        served.mint(agent, &[ARMS_GET, JOBS_LIST]);
        refused_as(
            &served.call(agent, true, JOBS_LIST, json!({})).await,
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "door=program, verb=vault.gpu.jobs.list (outside the five), Grant lists it",
        );
        refused_as(
            &served.call(agent, false, ARMS_GET, unknown_arm()).await,
            MEMORY_CODE_MODEL_UNAVAILABLE,
            "door=pumped run (no program), verb=vault.arms.get, Grant lists it",
        );
        Ok(())
    })
}
