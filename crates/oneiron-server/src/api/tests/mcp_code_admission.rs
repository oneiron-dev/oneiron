//! `execute_code` admission (C10, under the rate law of ARCH-0044 C5): a
//! burst of runs on one credential all complete, each waiting its turn past
//! the bound while a duplicate still gets `code_run_busy`; a run keeps its
//! permit until its worker ends, whether or not its caller is still waiting
//! for it; and a wait ends at its deadline with no run started.

use std::collections::BTreeSet;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use oneiron::context_board::StreamConnectionId;
use oneiron::engine_executor::{EngineExecutorConfig, EngineExecutorOutcome, JsCodeModeRuntime};
use oneiron::{BudgetLease, EdgeActorClass, EntityId, LlmBackend, Vault};
use tokio::sync::mpsc;

use super::support_mcp::{McpFixtureCodeBackend, McpFixtureCodeRuntime};
use crate::mcp::{
    CodeRunLimits, McpCodeExecutionError, McpCodeExecutionHost, McpCodeExecutionRequest,
    McpCodeModeProvider, McpConnectorScope, McpEngineNativeCodeHost, McpResolvedActor,
    mcp_code_run_id,
};
use crate::wire_telemetry::{LimitQuestions, LimitRow};

/// Holds every run's worker until the test opens it.
#[derive(Default)]
struct Gate {
    open: Mutex<bool>,
    opened: Condvar,
}

impl Gate {
    fn open(&self) {
        *self.open.lock().unwrap() = true;
        self.opened.notify_all();
    }
}

/// A provider whose sandbox runtime is built only once the gate opens, so a
/// run's worker thread stays alive, and its permit held, until the test says.
struct HeldProvider {
    backend: McpFixtureCodeBackend,
    lease: BudgetLease,
    gate: Arc<Gate>,
    entered: mpsc::UnboundedSender<()>,
}

impl McpCodeModeProvider for HeldProvider {
    fn backend(&self) -> &dyn LlmBackend {
        &self.backend
    }

    fn lease(&self) -> &BudgetLease {
        &self.lease
    }

    fn runtime(&self) -> Box<dyn JsCodeModeRuntime + Send> {
        let _ = self.entered.send(());
        let mut open = self.gate.open.lock().unwrap();
        while !*open {
            open = self.gate.opened.wait(open).unwrap();
        }
        Box::new(McpFixtureCodeRuntime)
    }

    fn executor_config(
        &self,
        _: &Vault,
        run_id: EntityId,
        task: &str,
    ) -> oneiron::Result<EngineExecutorConfig> {
        Ok(EngineExecutorConfig {
            run_id,
            task: task.to_owned(),
            prompt_package_root: oneiron::prompt::workspace_test_prompt_package_root()
                .expect("workspace test prompt package"),
            model: oneiron::ModelId::new("fixture/executor@v1").expect("fixture model id"),
            model_locality: oneiron::ModelLocality::OnDevice,
            seat_effort: None,
            global_tier: oneiron::ModelTierRef("fixture-tier".to_owned()),
            determinism: oneiron::code_run::CodeRunDeterminism::new(
                1_000,
                [7; oneiron::code_run::CODE_RUN_RNG_SEED_LEN],
            ),
            limits: oneiron::engine_executor::EngineExecutorLimits::default(),
        })
    }
}

/// A door that serves no agent verb: these runs never reach one.
struct NoVerbs;

impl oneiron::code_run::AgentVerbDoor for NoVerbs {
    fn call(
        &self,
        _: &oneiron::code_run::SelfAgentVerbCall,
        _: &oneiron::memory::HostWriteOrigin,
        _: oneiron::runtime_hooks::InvocationId,
    ) -> oneiron::Result<
        Result<oneiron::code_run::AgentVerbAnswer, oneiron::code_run::AgentVerbRefusal>,
    > {
        Ok(Err(oneiron::code_run::AgentVerbRefusal {
            code: oneiron::code_run::AGENT_VERB_DOOR_UNBOUND.to_owned(),
        }))
    }

    fn admit_run_call(
        &self,
        _: oneiron::code_run::RunCall,
    ) -> Result<Option<oneiron::claim::ScopedReadActorKey>, oneiron::code_run::AgentVerbRefusal>
    {
        Ok(None)
    }
}

/// An actor under one registered credential, named by its stream connection.
fn actor(credential: &str) -> McpResolvedActor {
    let actor_ref = EntityId::now();
    McpResolvedActor {
        auth: None,
        actor_ref,
        actor_class: EdgeActorClass::Agent,
        gate_actor_class: "agent",
        gate_actor_ref: actor_ref.to_hex(),
        scope: McpConnectorScope::vault_wide(),
        stream_connection: StreamConnectionId(format!("mcp-test:{credential}")),
        bound_verbs: None,
        subscription_ceiling: BTreeSet::new(),
    }
}

type Outcome = Result<EngineExecutorOutcome, McpCodeExecutionError>;

fn run<'a>(
    host: &'a McpEngineNativeCodeHost,
    vault: &Arc<Vault>,
    actor: &'a McpResolvedActor,
    run_ref: &'a str,
) -> std::pin::Pin<Box<dyn Future<Output = Outcome> + Send + 'a>> {
    host.execute(McpCodeExecutionRequest {
        vault: Arc::clone(vault),
        actor,
        run_ref,
        task: "summarize the launch plan",
        run_id: mcp_code_run_id(run_ref, actor),
        verbs: Arc::new(NoVerbs),
    })
}

/// The refusal a call gets without its run ever reaching a worker.
async fn refused(call: std::pin::Pin<Box<dyn Future<Output = Outcome> + Send + '_>>) -> String {
    let outcome = tokio::time::timeout(Duration::from_secs(10), call)
        .await
        .expect("an answer within its deadline");
    outcome.expect_err("refused").error_code().to_owned()
}

/// A host working on at most `total` runs at once, its runs' workers held
/// at `gate`; the receiver hears each worker start.
fn host(
    gate: &Arc<Gate>,
    total: usize,
    wait: Duration,
) -> (
    McpEngineNativeCodeHost,
    mpsc::UnboundedReceiver<()>,
    Arc<LimitQuestions>,
) {
    let (entered, workers) = mpsc::unbounded_channel();
    let questions = Arc::new(LimitQuestions::default());
    let host = McpEngineNativeCodeHost::new(
        Arc::new(HeldProvider {
            backend: McpFixtureCodeBackend,
            lease: BudgetLease::for_test("execute-code-admission"),
            gate: Arc::clone(gate),
            entered,
        }),
        CodeRunLimits { total, wait },
        Arc::clone(&questions),
    );
    (host, workers, questions)
}

/// Rule five at the code runs row: `callers` runs on one credential past a
/// bound of one all complete, and the row asks.
pub(super) async fn cross_the_runs(callers: usize) -> crate::admission::Crossing {
    let (_dir, server) = super::test_server();
    let vault = Arc::clone(&server.vault);
    let gate = Arc::new(Gate::default());
    gate.open();
    let (host, _workers, questions) = host(&gate, 1, Duration::from_secs(300));
    let fleet = actor("fleet");
    let run_refs: Vec<String> = (0..callers).map(|n| format!("cross-{n}")).collect();
    let outcomes = futures_util::future::join_all(
        run_refs
            .iter()
            .map(|run_ref| run(&host, &vault, &fleet, run_ref)),
    )
    .await;
    crate::admission::Crossing {
        refused: outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        asked: questions.latest(LimitRow::CodeRuns).is_some(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_burst_of_two_hundred_runs_on_one_credential_all_complete() {
    let (_dir, server) = super::test_server();
    let vault = Arc::clone(&server.vault);
    let gate = Arc::new(Gate::default());
    gate.open();
    let (host, _workers, questions) = host(&gate, 2, Duration::from_secs(300));
    let fleet = actor("fleet");
    let run_refs: Vec<String> = (0..200).map(|n| format!("burst-{n}")).collect();

    let outcomes = tokio::time::timeout(
        Duration::from_secs(600),
        futures_util::future::join_all(
            run_refs
                .iter()
                .map(|run_ref| run(&host, &vault, &fleet, run_ref)),
        ),
    )
    .await
    .expect("every run completes");
    for (run_ref, outcome) in run_refs.iter().zip(outcomes) {
        assert!(
            outcome.is_ok(),
            "{run_ref}: a queued run is served, never refused: {outcome:?}"
        );
    }
    assert!(
        questions.latest(LimitRow::CodeRuns).is_some(),
        "the burst crossed the row, which asked"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_keeps_its_permit_until_its_worker_ends_and_the_next_waits_for_it() {
    let (_dir, server) = super::test_server();
    let vault = Arc::clone(&server.vault);
    let gate = Arc::new(Gate::default());
    let (host, mut workers, _) = host(&gate, 1, Duration::from_secs(300));
    let (first, second) = (actor("first"), actor("second"));

    // The first credential's run reaches its worker; then its caller hangs up.
    let mut held = run(&host, &vault, &first, "run-a");
    tokio::select! {
        _ = &mut held => panic!("a held run finished before its gate opened"),
        _ = workers.recv() => {}
    }
    drop(held);

    // Its worker still runs, so its single-flight and its permit both stand:
    // a duplicate is busy, and another credential's run waits its turn.
    assert_eq!(
        refused(run(&host, &vault, &first, "run-a")).await,
        "code_run_busy"
    );
    let mut next = run(&host, &vault, &second, "run-b");
    assert!(
        tokio::time::timeout(Duration::from_millis(300), &mut next)
            .await
            .is_err(),
        "past the bound a run waits; it is never refused"
    );

    // Once the held worker ends, its permit passes to the waiting run.
    gate.open();
    let outcome = tokio::time::timeout(Duration::from_secs(60), next)
        .await
        .expect("the waiting run gets its turn when the held worker ends");
    assert!(outcome.is_ok(), "{outcome:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_run_that_waits_past_its_deadline_ends_with_no_run_started() {
    let (_dir, server) = super::test_server();
    let vault = Arc::clone(&server.vault);
    let gate = Arc::new(Gate::default());
    let (host, mut workers, _) = host(&gate, 1, Duration::from_millis(300));
    let (first, second) = (actor("first"), actor("second"));

    let mut held = run(&host, &vault, &first, "run-a");
    tokio::select! {
        _ = &mut held => panic!("a held run finished before its gate opened"),
        _ = workers.recv() => {}
    }
    let started = std::time::Instant::now();
    assert_eq!(
        refused(run(&host, &vault, &second, "run-b")).await,
        "code_run_waited_out"
    );
    assert!(
        started.elapsed() >= Duration::from_millis(300),
        "it waited its deadline rather than being refused at once"
    );
    assert!(workers.try_recv().is_err(), "no worker started for it");
    gate.open();
    let _ = tokio::time::timeout(Duration::from_secs(60), held).await;
}
