use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use super::*;
use crate::code_run::{AgentVerbDoor, AgentVerbRefusal, SelfAgentVerbCall, SelfMemorySearchCall};
use crate::memory::HostWriteOrigin;
use crate::task_verb::sdk::{AgentVerb, TaskCreateRequest};

/// A host's verb door reduced to the one verb this run calls: `tasks.create`
/// on the host's memory surface, under the origin the dispatcher hands it.
struct TaskCreateDoor {
    vault: Arc<Vault>,
    actor: WriteActor,
}

impl AgentVerbDoor for TaskCreateDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
    ) -> std::result::Result<serde_json::Value, AgentVerbRefusal> {
        let refused = |message: String| AgentVerbRefusal {
            code: "engine_error".to_owned(),
            message,
        };
        let input: TaskCreateRequest = serde_json::from_value(call.input.clone())
            .map_err(|error| refused(error.to_string()))?;
        let memory = self
            .vault
            .memory(self.actor.entity_ref(), self.actor.actor_class())
            .with_host_origin(origin.clone());
        let receipt = crate::task_verb::sdk::tasks_create(&memory, input)
            .map_err(|error| refused(error.code))?;
        serde_json::to_value(receipt).map_err(|error| refused(error.to_string()))
    }
}

/// One step that makes its bridge calls and keeps their answers. One that
/// `stops` then halts the process: the calls' writes are committed and the
/// step's checkpoint is not.
struct RecordedStep {
    calls: Vec<SelfCall>,
    stops: bool,
    answers: Vec<SelfDispatchOutcome>,
}

impl JsCodeModeRuntime for RecordedStep {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        for call in self.calls.clone() {
            self.answers.push(host.dispatch_self(call)?.outcome);
        }
        assert!(
            !self.stops,
            "the process stops before the step's checkpoint"
        );
        Ok(JsCodeModeStepOutcome::complete(""))
    }
}

fn written_tasks_and_claims(vault: &Vault) -> Vec<EntityId> {
    [
        crate::registry::ENTITY_TYPE_TASK,
        crate::registry::ENTITY_TYPE_CLAIM,
    ]
    .into_iter()
    .flat_map(|entity_type| vault.entities_by_type(entity_type).expect("read entities"))
    .collect()
}

fn create_task() -> SelfCall {
    SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: AgentVerb::TasksCreate,
        input: serde_json::json!({"spec": "summarize the open notes", "label": null}),
    })
}

/// A run whose one step writes through `tasks.create` on the host's verb door.
struct VerbWriteRun<'a> {
    vault: &'a Vault,
    gated_write: GatedActorWrite<'a>,
    config: EngineExecutorConfig,
}

impl<'a> VerbWriteRun<'a> {
    fn new(vault: &'a Arc<Vault>) -> Self {
        let actor_id = EntityId::from_bytes(crate::gate::FIRST_PARTY_CONNECTOR_ACTOR_ID)
            .expect("first-party actor id");
        vault
            .put_entity(
                &actor_id,
                ENTITY_TYPE_PERSON,
                range(1),
                1,
                b"first-party actor",
            )
            .expect("seed actor");
        let actor = WriteActor::new(actor_id, EdgeActorClass::Agent);
        let gated_write = GatedActorWrite::new(vault, actor, "verb-write-resume")
            .expect("gated actor write")
            .with_agent_verb_door(Arc::new(TaskCreateDoor {
                vault: Arc::clone(vault),
                actor,
            }));
        Self {
            vault,
            gated_write,
            config: executor_config(entity(0xE7), EngineExecutorLimits::default()),
        }
    }

    /// Runs `runtime` as the run's steps under `config`; a step that stops
    /// the process ends the run there.
    fn run(
        &self,
        config: &EngineExecutorConfig,
        runtime: &mut dyn JsCodeModeRuntime,
    ) -> std::thread::Result<EngineExecutorResult<EngineExecutorOutcome>> {
        let script = "await self.memory.tasks.create({spec: 'summarize the open notes'});";
        let backend = FixtureBackend::new([script, script]);
        let lease = BudgetLease::for_test("executor-lease");
        catch_unwind(AssertUnwindSafe(|| {
            let mut executor =
                EngineNativeExecutor::new(self.vault, &backend, &lease, runtime, &self.gated_write);
            block_on_ready(executor.run(config))
        }))
    }

    /// The step's calls `first`, the last of them a `tasks.create` that
    /// commits, then the process stops before the step's checkpoint. Returns
    /// that call's answer.
    fn stop_after(&self, first: Vec<SelfCall>) -> SelfDispatchOutcome {
        let before = written_tasks_and_claims(self.vault);
        let mut step = RecordedStep {
            calls: first,
            stops: true,
            answers: Vec::new(),
        };
        assert!(
            self.run(&self.config, &mut step).is_err(),
            "the process stopped"
        );
        assert!(
            written_tasks_and_claims(self.vault).len() > before.len(),
            "the write committed before the process stopped"
        );
        let first = step.answers.pop().expect("the first attempt's answer");
        assert!(matches!(first, SelfDispatchOutcome::AgentVerb(_)));
        first
    }

    /// The same run resumed under `config` as `runtime`. Returns the run's
    /// result, after checking the resumed run wrote nothing new.
    fn resume(
        &self,
        config: &EngineExecutorConfig,
        runtime: &mut dyn JsCodeModeRuntime,
    ) -> EngineExecutorResult<EngineExecutorOutcome> {
        let committed = written_tasks_and_claims(self.vault);
        let run = self.run(config, runtime);
        assert_eq!(
            written_tasks_and_claims(self.vault),
            committed,
            "the resumed run writes no second task"
        );
        run.expect("the resumed run returns")
    }
}

/// The step's calls as one resumed step that completes.
fn resumed_step(calls: Vec<SelfCall>) -> RecordedStep {
    RecordedStep {
        calls,
        stops: false,
        answers: Vec::new(),
    }
}

/// A step makes the calls `first`, the last of them a `tasks.create` that
/// commits; the process then stops before the step's checkpoint. The same
/// step resumes as `resumed`, whose last call is the same `tasks.create`.
/// Returns the first attempt's answer to it and the resumed one's.
fn resume_after_a_lost_checkpoint(
    first: Vec<SelfCall>,
    resumed: Vec<SelfCall>,
) -> (SelfDispatchOutcome, SelfDispatchOutcome) {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    let first = run.stop_after(first);
    let mut resumed = resumed_step(resumed);
    let outcome = run.resume(&run.config, &mut resumed);
    assert_eq!(
        outcome.expect("the resumed run").status,
        EngineExecutorStatus::Complete
    );
    (first, resumed.answers.pop().expect("the resumed answer"))
}

/// Review repro (Greptile, #1338): a code-mode `tasks.create` commits before
/// its step's checkpoint. Resumed, the step makes the same call again and
/// gets the first receipt back; the vault holds the one task.
#[test]
fn resumed_step_returns_the_committed_verb_write_instead_of_writing_again() {
    let (first, resumed) = resume_after_a_lost_checkpoint(vec![create_task()], vec![create_task()]);
    assert_eq!(
        resumed, first,
        "the resumed call answers with the first receipt"
    );
}

/// Review repro (Astra R3, #1338): the resumed step's code is generated again
/// and may place the same write at another bridge position. Here the first
/// attempt wrote behind a search and the resumed one writes first; the write
/// is still the one the first attempt committed.
#[test]
fn resumed_step_that_moves_its_write_still_gets_the_first_receipt() {
    let search = SelfCall::MemorySearch(SelfMemorySearchCall::new("open notes", 4));
    let (first, resumed) =
        resume_after_a_lost_checkpoint(vec![search, create_task()], vec![create_task()]);
    assert_eq!(
        resumed, first,
        "the moved call answers with the first receipt"
    );
}

/// Review repro (Astra R4, #1338): the resumed step's code is generated again
/// and may make its write with another input, here `label` omitted where the
/// first attempt passed `null`. The step's first write is the one the first
/// attempt committed, so the changed call is refused, never written again.
#[test]
fn resumed_step_that_changes_its_write_is_refused_not_written_twice() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    run.stop_after(vec![create_task()]);
    let changed = SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: AgentVerb::TasksCreate,
        input: serde_json::json!({"spec": "summarize the open notes"}),
    });
    let outcome = run.resume(&run.config, &mut resumed_step(vec![changed]));
    assert!(
        matches!(
            outcome,
            Err(EngineExecutorError::Engine(Error::InvariantViolation(_)))
        ),
        "{outcome:?}"
    );
}

/// Review repro (Astra R5, #1338): a run's clock and config are saved when it
/// starts. The process stops after the first step's write and before its
/// checkpoint; the run's record already holds the clock it started with, and
/// resuming it under another task is refused.
#[test]
fn a_run_stopped_before_its_first_checkpoint_keeps_its_clock_and_config() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    run.stop_after(vec![create_task()]);
    let record = vault
        .get_code_run_replay_record(&run.config.run_id)
        .expect("read the run's record")
        .expect("the run's record outlives the stop");
    assert_eq!(record.determinism, run.config.determinism);

    let other_task = EngineExecutorConfig {
        task: "forget the project status".to_owned(),
        ..run.config.clone()
    };
    let mut resumed = resumed_step(vec![create_task()]);
    let outcome = run.resume(&other_task, &mut resumed);
    assert!(
        matches!(
            outcome,
            Err(EngineExecutorError::Engine(Error::InvalidConfig(_)))
        ),
        "{outcome:?}"
    );
    assert!(resumed.answers.is_empty(), "the refused run made no call");
}

/// Review repro (Astra R8, #1338): the resumed step's code is generated again
/// and may leave its write out. Here it only reads and carries on, and the
/// next step makes the write. The step's write is the one the first attempt
/// committed, so the resumed step is refused before its checkpoint, never
/// written again by a later step.
#[test]
fn resumed_step_that_leaves_its_write_out_is_refused_not_written_later() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    run.stop_after(vec![create_task()]);
    let search = SelfCall::MemorySearch(SelfMemorySearchCall::new("open notes", 4));
    let mut resumed = FixtureRuntime::new([
        JsCodeModeStepOutcome::pending("read"),
        JsCodeModeStepOutcome::complete("wrote"),
    ])
    .with_calls([vec![search], vec![create_task()]]);
    let outcome = run.resume(&run.config, &mut resumed);
    assert!(
        matches!(
            outcome,
            Err(EngineExecutorError::Engine(Error::InvariantViolation(_)))
        ),
        "{outcome:?}"
    );
}
