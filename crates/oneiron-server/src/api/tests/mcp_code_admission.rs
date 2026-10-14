//! `execute_code` admission (C10): a distinct run past the bound is refused
//! with `code_run_saturated` while a duplicate still gets `code_run_busy`, and
//! a run keeps its permit until its worker ends, whether or not its caller is
//! still waiting for it.

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
    ) -> Result<oneiron::code_run::AgentVerbAnswer, oneiron::code_run::AgentVerbRefusal> {
        Err(oneiron::code_run::AgentVerbRefusal {
            code: oneiron::code_run::AGENT_VERB_DOOR_UNBOUND.to_owned(),
        })
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
        .expect("a refusal never waits");
    outcome.expect_err("refused").error_code().to_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn execute_code_runs_hold_their_permits_until_their_workers_end() {
    let (_dir, server) = super::test_server();
    let vault = Arc::clone(&server.vault);
    let gate = Arc::new(Gate::default());
    let (entered, mut workers) = mpsc::unbounded_channel();
    let host = McpEngineNativeCodeHost::new(
        Arc::new(HeldProvider {
            backend: McpFixtureCodeBackend,
            lease: BudgetLease::for_test("execute-code-admission"),
            gate: Arc::clone(&gate),
            entered,
        }),
        CodeRunLimits {
            total: 2,
            per_credential: 1,
        },
    );
    let (first, second, third) = (actor("first"), actor("second"), actor("third"));

    // The first credential's run reaches its worker; then its caller hangs up.
    let mut held = run(&host, &vault, &first, "run-a");
    tokio::select! {
        _ = &mut held => panic!("a held run finished before its gate opened"),
        _ = workers.recv() => {}
    }
    drop(held);

    // Its worker still runs, so its single-flight and its permit both stand.
    assert_eq!(
        refused(run(&host, &vault, &first, "run-a")).await,
        "code_run_busy"
    );
    assert_eq!(
        refused(run(&host, &vault, &first, "run-b")).await,
        "code_run_saturated",
        "one credential holds at most its share, and a caller hanging up frees none of it"
    );

    // A second credential takes the last permit; a third finds none.
    let mut other = run(&host, &vault, &second, "run-c");
    tokio::select! {
        _ = &mut other => panic!("a held run finished before its gate opened"),
        _ = workers.recv() => {}
    }
    assert_eq!(
        refused(run(&host, &vault, &third, "run-d")).await,
        "code_run_saturated",
        "past the total, a new run is refused rather than queued"
    );

    // Once the workers end, their permits return and new runs start.
    gate.open();
    let _ = tokio::time::timeout(Duration::from_secs(60), other)
        .await
        .expect("a released run ends");
    let admitted = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match run(&host, &vault, &first, "run-b").await {
                Err(McpCodeExecutionError::RunSaturated) => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                outcome => break outcome,
            }
        }
    })
    .await
    .expect("the first credential's permit returns when its worker ends");
    assert!(
        !matches!(
            admitted,
            Err(McpCodeExecutionError::RunBusy | McpCodeExecutionError::RunSaturated)
        ),
        "{admitted:?}"
    );
}
