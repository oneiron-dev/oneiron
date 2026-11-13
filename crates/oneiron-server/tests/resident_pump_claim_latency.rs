//! FIX AGENT-RUN-START-LATENCY-4S, fix 1: the agent run pump claims a run
//! dispatched to it while idle on that dispatch's wake.
//!
//! The pump wakes on the vault's attempt signal. It used to wait one
//! `PASS_SPACING` (1 s) after every wake before its pass, so a run
//! dispatched to an idle pump was claimed a second or more after its
//! dispatch, and every agent run started that much later (a project mint
//! starts three in a row). The pump now passes at once when a commit queued
//! a ready run that no pass has seen; a burst of other commits still costs
//! one pass a second.
//!
//! The server is the one `serve` builds for a vault with code mode on (the
//! checked-in QuickJS component, the fixture prompt package, a local fake
//! model), and the test door starts its pump as `serve` does. The test waits
//! until the vault has sent no attempt signal for two seconds, so the pump
//! sits on its wake with no spacing pending, then dispatches the seeded
//! default agent and polls the run's attempt row until it leaves Queued.
//!
//! Fleet command: `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked
//! -p oneiron-server --all-features --features oneiron/test-support --test
//! resident_pump_claim_latency`.
#![cfg(oneiron_test_support)]

#[path = "support/fake_llm.rs"]
mod fake_llm;

use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use fake_llm::FakeLlm;
use oneiron::agent_dispatch::{
    AgentDispatchOutcome, AgentDispatchTarget, AgentDispatcher, AgentSpawnContext,
    DEFAULT_BASE_LOGICAL_ID, DispatchAgent,
};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptState};
use oneiron::authority::MachineRole;
use oneiron::{Vault, VaultConfig};
use oneiron_keystore::MemoryKeystore;
use oneiron_server::ai_host::AiHost;
use oneiron_server::config::{SyncServerConfig, models::ModelsConfig};
use oneiron_server::test_doors::resident_pump::spawn_resident_pump;
use oneiron_server::{ENGINE_THREAD_STACK_BYTES, server::SyncServer};
use tokio::sync::broadcast::{Receiver, error::RecvError};

/// Half the old floor. A claim on the dispatch's wake is one pass and one
/// write; a claim after the spacing comes 1 s or more after the dispatch.
const CLAIM_BOUND: Duration = Duration::from_millis(500);
/// How long the vault sends no attempt signal before the dispatch: past one
/// `PASS_SPACING`, so no spaced pass is pending.
const QUIET: Duration = Duration::from_secs(2);
/// How long the vault may take to go quiet after the pump starts.
const SETTLE_CAP: Duration = Duration::from_secs(60);
/// How long the run may stay Queued before the test gives up on its claim.
const CLAIM_CAP: Duration = Duration::from_secs(10);
/// How often the run's attempt row is read.
const POLL: Duration = Duration::from_millis(5);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs()
}

/// Code mode on, the Dreamer and the workflow pump off (their passes would
/// keep the vault busy), and the type check off (its load is not the
/// pump's).
fn models_text(base_url: &str) -> String {
    let prompts = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../oneiron/tests/fixtures/prompts")
        .canonicalize()
        .expect("the fixture prompt package");
    format!(
        "default = \"local:test-model\"\nextraction_egress = true\n\
         [dreamer]\nenabled = false\n[workflows]\nenabled = false\n\
         [code_mode]\nprompt_package = {prompts:?}\n[code_mode.check]\nmode = \"off\"\n\
         [providers.local]\nkind = \"local-openai-compat\"\nbase_url = \"{base_url}\"\n",
        prompts = prompts.display().to_string(),
    )
}

/// Runs `test` on an engine-sized stack and runtime. The claimed run goes
/// on on its own thread after the test's last read, so the runtime's
/// shutdown does not wait for it.
fn on_engine_stack<F, Fut>(name: &str, test: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()>,
{
    let run = std::thread::Builder::new()
        .name(name.into())
        .stack_size(ENGINE_THREAD_STACK_BYTES)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(ENGINE_THREAD_STACK_BYTES)
                .enable_all()
                .build()
                .expect("engine-sized test runtime");
            runtime.block_on(test());
            runtime.shutdown_timeout(Duration::from_secs(10));
        })
        .expect("spawn the engine-sized test thread");
    if let Err(panic) = run.join() {
        std::panic::resume_unwind(panic);
    }
}

/// Waits until the vault has sent no attempt signal for [`QUIET`].
async fn wait_until_quiet(signals: &mut Receiver<()>) {
    let start = Instant::now();
    loop {
        match tokio::time::timeout(QUIET, signals.recv()).await {
            Err(_) => return,
            Ok(Err(RecvError::Closed)) => panic!("the vault's attempt signal closed"),
            Ok(_) => {}
        }
        assert!(
            start.elapsed() < SETTLE_CAP,
            "the vault never went {QUIET:?} without an attempt signal"
        );
    }
}

/// The time from `from` until the run's attempt row leaves Queued: its
/// claim (a run that fails fast may already have ended).
async fn claimed_after(vault: &Vault, id: AttemptId, from: Instant) -> Duration {
    loop {
        let row = AttemptQueue::new(vault)
            .get(id)
            .expect("read the run's attempt")
            .expect("the run's attempt exists");
        if !matches!(row.state, AttemptState::Queued | AttemptState::Scheduled) {
            return from.elapsed();
        }
        assert!(
            from.elapsed() < CLAIM_CAP,
            "the pump did not claim the run within {CLAIM_CAP:?}"
        );
        tokio::time::sleep(POLL).await;
    }
}

#[test]
fn queued_agent_run_is_claimed_within_half_a_second_of_its_dispatch() {
    on_engine_stack("resident-pump-claim-latency", || async {
        let model = FakeLlm::start(Vec::new(), None).await;
        let dir = tempfile::tempdir().expect("temporary vault directory");
        let vault = Arc::new(Vault::open(dir.path(), VaultConfig::device()).expect("open vault"));
        // The keystore goes in BEFORE the server: construction roots the vault.
        vault.install_device_keystore(Arc::new(MemoryKeystore::new()));
        let server = SyncServer::new(
            Arc::clone(&vault),
            SyncServerConfig {
                auth_secret: Some("resident-pump-claim-latency".into()),
                ..Default::default()
            },
        )
        .expect("create server");
        let issuer = vault.load_host_slip_issuer().expect("host slip issuer");
        let _owner_slip = vault
            .ensure_host_root_slip(&issuer)
            .expect("owner root slip");
        vault
            .ensure_serving_install_profile(&issuer, MachineRole::Unanswered)
            .expect("this install's live machine profile");
        let models =
            ModelsConfig::from_toml(&models_text(&model.base_url), None).expect("models config");
        let (server, host) = AiHost::attach(server, Some(&models)).await;
        let server = Arc::new(server);

        let mut signals = AttemptQueue::new(&vault).subscribe();
        let pump = spawn_resident_pump(&server)
            .expect("code mode binds an engine-native code host, so the pump starts");
        wait_until_quiet(&mut signals).await;

        let (agent, _) = vault
            .get_seeded_agent_definition_by_logical_id(DEFAULT_BASE_LOGICAL_ID)
            .expect("read the seeded agents")
            .expect("the default agent is seeded");
        let dispatched = AgentDispatcher::new(&vault)
            .dispatch_with_context(
                DispatchAgent {
                    target: AgentDispatchTarget::Custom(agent),
                    parent_attempt: None,
                    dedupe_key: None,
                    run_id: Some("resident-pump-claim-latency".to_owned()),
                    now: unix_now(),
                },
                AgentSpawnContext::default().with_depth_remaining(1),
            )
            .expect("dispatch the default agent");
        let dispatched_at = Instant::now();
        let AgentDispatchOutcome::Dispatched(status) = dispatched else {
            panic!("the dispatch queues one fresh run");
        };
        let took = claimed_after(&vault, status.attempt.id, dispatched_at).await;

        pump.abort();
        host.shutdown().await;
        assert!(
            took < CLAIM_BOUND,
            "the pump claimed the run {took:?} after its dispatch; the bound is {CLAIM_BOUND:?}"
        );
    });
}
