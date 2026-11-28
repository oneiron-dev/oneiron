//! T4 for FIX CODE-MODE-LENDING-W11: a kept verb write is read back by its
//! original verb.
//!
//! Red when Part 1 item 3e is undone: without the producer check in
//! `kept_write_answer`, a door that refuses the receipt's verb still releases
//! the kept answer.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use super::*;
use crate::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall,
};
use crate::memory::HostWriteOrigin;
use crate::task_verb::sdk::{AgentVerb, TaskCreateRequest};

/// A host's verb door reduced to `tasks.create`, like `TaskCreateDoor` in
/// `agent_verb_regressions.rs`: its answer is the task receipt. Once
/// `refuses_recorded_verb`, it refuses `admit_recorded_verb` for `TasksCreate`
/// only, while still admitting the generic recorded read and every other verb.
struct RecordedVerbDoor {
    vault: Arc<Vault>,
    actor: WriteActor,
    refuses_recorded_verb: std::sync::atomic::AtomicBool,
    observed_recorded_verbs: std::sync::Mutex<Vec<AgentVerb>>,
}

impl RecordedVerbDoor {
    fn new(vault: &Arc<Vault>, actor: WriteActor) -> Arc<Self> {
        Arc::new(Self {
            vault: Arc::clone(vault),
            actor,
            refuses_recorded_verb: std::sync::atomic::AtomicBool::new(false),
            observed_recorded_verbs: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn answer(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
    ) -> std::result::Result<AgentVerbAnswer, AgentVerbRefusal> {
        let refused = || AgentVerbRefusal {
            code: "engine_error".to_owned(),
            hook_notice: None,
            reason_codes: Vec::new(),
        };
        let input: TaskCreateRequest =
            serde_json::from_value(call.input.clone()).map_err(|_| refused())?;
        let memory = self
            .vault
            .memory(self.actor.entity_ref(), self.actor.actor_class())
            .with_host_origin(origin.clone());
        let receipt = crate::task_verb::sdk::tasks_create(&memory, input).map_err(|_| refused())?;
        let answer = serde_json::to_value(receipt).map_err(|_| refused())?;
        Ok(AgentVerbAnswer {
            output: answer,
            rows: Some(Vec::new()),
            hook_notice: None,
            observations: Vec::new(),
            hooks: Vec::new(),
            stored_output: None,
        })
    }
}

impl AgentVerbDoor for RecordedVerbDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        _: crate::runtime_hooks::InvocationId,
    ) -> crate::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(self.answer(call, origin))
    }

    fn admit_run_call(
        &self,
        _call: RunCall,
    ) -> std::result::Result<Option<crate::claim::ScopedReadActorKey>, AgentVerbRefusal> {
        Ok(None)
    }

    fn admit_recorded_verb(&self, verb: AgentVerb) -> std::result::Result<(), AgentVerbRefusal> {
        self.observed_recorded_verbs
            .lock()
            .expect("observed recorded verbs")
            .push(verb);
        if self
            .refuses_recorded_verb
            .load(std::sync::atomic::Ordering::SeqCst)
            && verb == AgentVerb::TasksCreate
        {
            return Err(AgentVerbRefusal {
                code: "recorded_verb_refused".to_owned(),
                hook_notice: None,
                reason_codes: vec!["recorded.verb.revoked".to_owned()],
            });
        }
        Ok(())
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

/// The same input offered as a different write verb: only the verb differs,
/// so a refusal names the producer check's verb selection, not the input.
fn update_task() -> SelfCall {
    SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: AgentVerb::TasksUpdate,
        input: serde_json::json!({"spec": "summarize the open notes", "label": null}),
    })
}

/// A run whose one step writes through `tasks.create` on the host's verb door.
struct VerbWriteRun<'a> {
    vault: &'a Vault,
    gated_write: GatedActorWrite<'a>,
    door: Arc<RecordedVerbDoor>,
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
        crate::conversation_dag::fixtures::grant_reads(vault, actor);
        let door = RecordedVerbDoor::new(vault, actor);
        let gated_write = GatedActorWrite::new(vault, door.actor, "verb-write-resume")
            .expect("gated actor write")
            .with_agent_verb_door(door.clone());
        Self {
            vault,
            gated_write,
            door,
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

/// T4 (FIX CODE-MODE-LENDING-W11): the resumed step's kept answer is refused
/// where its original verb is refused now, even when the retry offers a
/// different write verb the door admits; the receipt's marker stays first on
/// the persisted ruling, and admitted again, the first receipt comes back. Red
/// when Part 1 item 3e is undone.
#[test]
fn a_kept_write_is_read_back_by_its_original_verb() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    let first = run.stop_after(vec![create_task()]);

    run.door
        .refuses_recorded_verb
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut refused = resumed_step(vec![update_task()]);
    let outcome = run.resume(&run.config, &mut refused);
    assert!(
        matches!(
            outcome,
            Err(EngineExecutorError::Engine(Error::InvariantViolation(_)))
        ),
        "a step whose write was refused does not close: {outcome:?}"
    );
    assert_eq!(
        refused.answers,
        vec![SelfDispatchOutcome::Denied(
            crate::code_run::SelfDeniedResult {
                effect: SelfEffect::AgentVerb,
                outcome: "recorded_verb_refused".to_owned(),
                reason_codes: vec!["recorded.verb.revoked".to_owned()],
                hook_notice: None,
            }
        )],
        "the guest gets the door's refusal for the original verb"
    );
    assert_eq!(
        run.door
            .observed_recorded_verbs
            .lock()
            .expect("observed recorded verbs")
            .clone(),
        vec![AgentVerb::TasksCreate],
        "the producer check names the receipt's original verb, not the offered call"
    );

    let step_start = 0u64.to_le_bytes();
    let ordinal = 0u64.to_le_bytes();
    let receipt_id = crate::store::executor_speech_identity::derived_executor_id(
        crate::entity_id::derived_domains::EXECUTOR_AGENT_VERB_RECEIPT,
        &[
            "verb-write-resume".as_bytes(),
            run.config.run_id.as_bytes(),
            &step_start,
            &ordinal,
        ],
    )
    .expect("receipt id");
    let receipt = vault
        .get_code_run_replay_record(&receipt_id)
        .expect("read the write receipt")
        .expect("the write receipt outlives the refusal");
    let ruling = receipt.bridge_calls.last().expect("the refusal ruling");
    let SelfDispatchOutcome::Denied(denied) =
        ruling.recorded_outcome().expect("the ruling decodes")
    else {
        panic!("the ruling must deny");
    };
    assert_eq!(
        denied.reason_codes,
        vec![
            "kept_answer_refused".to_owned(),
            "recorded.verb.revoked".to_owned()
        ],
        "the persisted ruling carries the receipt's marker first"
    );

    run.door
        .refuses_recorded_verb
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut admitted = resumed_step(vec![create_task()]);
    let outcome = run.resume(&run.config, &mut admitted);
    assert_eq!(
        outcome.expect("the admitted resume").status,
        EngineExecutorStatus::Complete
    );
    assert_eq!(
        admitted.answers.pop().expect("the resumed answer"),
        first,
        "the admitted resume answers with the first receipt"
    );
}
