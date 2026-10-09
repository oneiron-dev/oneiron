use std::sync::Arc;

use super::speech_identity_regressions::initial_executor_replay_record;
use super::*;
use crate::code_run::{AgentVerbDoor, AgentVerbRefusal, SelfAgentVerbCall};
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

/// One step that makes one bridge call and keeps its answer. Given a competing
/// replay record, it then loses the step checkpoint's compare-and-set: the
/// call's write is committed and the step's checkpoint is not, as when the
/// process stops between the two.
struct OneCallStep<'a> {
    vault: &'a Vault,
    call: SelfCall,
    competing_record: Option<CodeRunReplayRecord>,
    answers: Vec<SelfDispatchOutcome>,
}

impl JsCodeModeRuntime for OneCallStep<'_> {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        self.answers
            .push(host.dispatch_self(self.call.clone())?.outcome);
        if let Some(record) = self.competing_record.take() {
            self.vault.put_code_run_replay_record(&record)?;
        }
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

/// Review repro (#1338): a code-mode `tasks.create` commits before its step's
/// checkpoint. A process that stops in that window resumes the same step at
/// the same bridge position; the resumed call answers with the first receipt
/// and the vault holds the one task the first attempt wrote.
#[test]
fn resumed_step_returns_the_committed_verb_write_instead_of_writing_again() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
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
    let gated_write = GatedActorWrite::new(&vault, actor, "verb-write-resume")
        .expect("gated actor write")
        .with_agent_verb_door(Arc::new(TaskCreateDoor {
            vault: Arc::clone(&vault),
            actor,
        }));
    let config = executor_config(entity(0xE7), EngineExecutorLimits::default());
    let lease = BudgetLease::for_test("executor-lease");
    let script = "await self.memory.tasks.create({spec: 'summarize the open notes'});";
    let call = SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: AgentVerb::TasksCreate,
        input: serde_json::json!({"spec": "summarize the open notes", "label": null}),
    });
    let before = written_tasks_and_claims(&vault);

    let backend = FixtureBackend::new([script]);
    let mut stopped = OneCallStep {
        vault: &vault,
        call: call.clone(),
        competing_record: Some(initial_executor_replay_record(&vault, &config)),
        answers: Vec::new(),
    };
    let error = {
        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut stopped, &gated_write);
        block_on_ready(executor.run(&config)).expect_err("the step loses its checkpoint")
    };
    assert!(matches!(
        error,
        EngineExecutorError::Engine(Error::ConcurrentWrite(_))
    ));
    let committed = written_tasks_and_claims(&vault);
    assert!(
        committed.len() > before.len(),
        "the write committed before the checkpoint was lost"
    );

    let backend = FixtureBackend::new([script]);
    let mut resumed = OneCallStep {
        vault: &vault,
        call,
        competing_record: None,
        answers: Vec::new(),
    };
    let outcome = {
        let mut executor =
            EngineNativeExecutor::new(&vault, &backend, &lease, &mut resumed, &gated_write);
        block_on_ready(executor.run(&config)).expect("the resumed run")
    };
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(
        written_tasks_and_claims(&vault),
        committed,
        "the resumed step writes no second task"
    );
    assert!(matches!(
        stopped.answers.as_slice(),
        [SelfDispatchOutcome::AgentVerb(_)]
    ));
    assert_eq!(
        resumed.answers, stopped.answers,
        "the resumed call answers with the first receipt"
    );
}
