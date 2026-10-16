use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use super::*;
use crate::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall,
    SelfMemorySearchCall,
};
use crate::memory::HostWriteOrigin;
use crate::task_verb::sdk::{AgentVerb, TaskCreateRequest};

/// A host's verb door reduced to the one verb this run calls: `tasks.create`
/// on the host's memory surface, under the origin the dispatcher hands it.
/// Its answer is the task receipt, with `extra` fields beside it. Once
/// `closed`, it refuses every call as the MCP door refuses a revoked slip's;
/// one that `refuses_kept` refuses reading a kept answer back, and only that,
/// in a gate's own word once `refuses_kept_as_a_gate`. `on_kept_read` runs
/// once, as the door rules on the next kept read.
struct TaskCreateDoor {
    vault: Arc<Vault>,
    actor: WriteActor,
    extra: serde_json::Map<String, serde_json::Value>,
    closed: std::sync::atomic::AtomicBool,
    refuses_kept: std::sync::atomic::AtomicBool,
    refuses_kept_as_a_gate: std::sync::atomic::AtomicBool,
    on_kept_read: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

impl TaskCreateDoor {
    fn new(
        vault: &Arc<Vault>,
        actor: WriteActor,
        extra: serde_json::Map<String, serde_json::Value>,
    ) -> Arc<Self> {
        Arc::new(Self {
            vault: Arc::clone(vault),
            actor,
            extra,
            closed: std::sync::atomic::AtomicBool::new(false),
            refuses_kept: std::sync::atomic::AtomicBool::new(false),
            refuses_kept_as_a_gate: std::sync::atomic::AtomicBool::new(false),
            on_kept_read: std::sync::Mutex::new(None),
        })
    }

    fn admits(&self) -> std::result::Result<(), AgentVerbRefusal> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(AgentVerbRefusal {
                code: "mcp_auth_required".to_owned(),
            });
        }
        Ok(())
    }
}

impl TaskCreateDoor {
    fn answer(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
    ) -> std::result::Result<AgentVerbAnswer, AgentVerbRefusal> {
        self.admits()?;
        let refused = || AgentVerbRefusal {
            code: "engine_error".to_owned(),
        };
        let input: TaskCreateRequest =
            serde_json::from_value(call.input.clone()).map_err(|_| refused())?;
        let memory = self
            .vault
            .memory(self.actor.entity_ref(), self.actor.actor_class())
            .with_host_origin(origin.clone());
        let receipt = crate::task_verb::sdk::tasks_create(&memory, input).map_err(|_| refused())?;
        let mut answer = serde_json::to_value(receipt).map_err(|_| refused())?;
        if let Some(fields) = answer.as_object_mut() {
            fields.extend(self.extra.clone());
        }
        Ok(AgentVerbAnswer {
            output: answer,
            rows: Some(Vec::new()),
        })
    }
}

impl AgentVerbDoor for TaskCreateDoor {
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
        call: RunCall,
    ) -> std::result::Result<Option<crate::claim::ScopedReadActorKey>, AgentVerbRefusal> {
        if call == RunCall::RecordedOutput {
            let hook = self.on_kept_read.lock().expect("kept-read hook").take();
            if let Some(hook) = hook {
                hook();
            }
        }
        if call == RunCall::RecordedOutput
            && self.refuses_kept.load(std::sync::atomic::Ordering::SeqCst)
        {
            let as_a_gate = self
                .refuses_kept_as_a_gate
                .load(std::sync::atomic::Ordering::SeqCst);
            return Err(AgentVerbRefusal {
                code: if as_a_gate { "deny" } else { "read_refused" }.to_owned(),
            });
        }
        self.admits().map(|()| None)
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
    door: Arc<TaskCreateDoor>,
    config: EngineExecutorConfig,
}

impl<'a> VerbWriteRun<'a> {
    fn new(vault: &'a Arc<Vault>) -> Self {
        Self::answering(vault, serde_json::Map::new())
    }

    /// A run whose door adds `extra` fields to each answer.
    fn answering(vault: &'a Arc<Vault>, extra: serde_json::Map<String, serde_json::Value>) -> Self {
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
        Self::through(vault, TaskCreateDoor::new(vault, actor, extra))
    }

    /// The same run, made through `door`, as another attempt of it is.
    fn through(vault: &'a Arc<Vault>, door: Arc<TaskCreateDoor>) -> Self {
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
/// It is refused where it is made, not answered with the first call's
/// receipt: a step that went on from that answer would make its next write.
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
    let next = SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: AgentVerb::TasksCreate,
        input: serde_json::json!({"spec": "file the summary"}),
    });
    let outcome = run.resume(&run.config, &mut resumed_step(vec![changed, next]));
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

/// Review repro (Astra R11, #1338): a write the bridge recorded after halting
/// never met its receipt. Resumed, the step's speech changed and is refused,
/// which halts the bridge; the step's write after it is recorded, never
/// dispatched. The step is refused before its checkpoint, so the next attempt
/// makes the step's write again and gets the first receipt, not a new task.
#[test]
fn a_write_recorded_after_the_bridge_halted_does_not_close_the_step() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    let speak = |text: &str| SelfCall::Speak(SelfSpeechCall::new(text));
    run.stop_after(vec![speak("Starting"), create_task()]);

    let mut halted = resumed_step(vec![speak("Trying again"), create_task()]);
    let outcome = run.resume(&run.config, &mut halted);
    assert!(
        matches!(outcome, Err(EngineExecutorError::Engine(_))),
        "{outcome:?}"
    );
    let record = vault
        .get_code_run_replay_record(&run.config.run_id)
        .expect("read the run's record")
        .expect("the run's record");
    assert!(
        record.step_checkpoints.is_empty(),
        "the halted step left no checkpoint"
    );

    let mut again = resumed_step(vec![create_task()]);
    let outcome = run.resume(&run.config, &mut again);
    assert_eq!(
        outcome.expect("the step made again").status,
        EngineExecutorStatus::Complete
    );
}

/// Review repro (Astra R12, #1338): a resumed write's answer is read back from
/// its receipt's JSON, and a float in it may move by one unit in the last
/// place: without serde_json's `float_roundtrip`, 2.0030397744267762e-253
/// reads back as 2.003039774426776e-253. The step that makes the same call
/// again still meets its receipt and completes.
#[test]
fn resumed_write_whose_answer_holds_a_float_still_closes_its_step() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let mut extra = serde_json::Map::new();
    extra.insert(
        "probability".to_owned(),
        serde_json::json!(2.0030397744267762e-253),
    );
    let run = VerbWriteRun::answering(&vault, extra);
    run.stop_after(vec![create_task()]);
    let outcome = run.resume(&run.config, &mut resumed_step(vec![create_task()]));
    assert_eq!(
        outcome.expect("the resumed run").status,
        EngineExecutorStatus::Complete
    );
}

/// Review repro (Astra, #1405): a step resumed after its write committed
/// answers that write from its kept receipt, and the door never ruled on that
/// read: a run whose slip was revoked before the repeated call still got the
/// kept answer. The door now rules on the kept answer as on any recorded
/// output. Closed, the guest gets the door's refusal, the vault keeps its one
/// write and the step does not close; open again, the step gets the first
/// receipt back.
#[test]
fn a_closed_door_refuses_a_resumed_write_its_kept_answer() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    let first = run.stop_after(vec![create_task()]);

    run.door
        .closed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut refused = resumed_step(vec![create_task()]);
    let outcome = run.resume(&run.config, &mut refused);
    assert!(
        matches!(
            outcome,
            Err(EngineExecutorError::Engine(Error::InvariantViolation(_)))
        ),
        "a step whose write was refused does not close: {outcome:?}"
    );
    assert_eq!(
        refused.answers.pop().expect("the refused answer"),
        SelfDispatchOutcome::Denied(crate::code_run::SelfDeniedResult {
            effect: SelfEffect::AgentVerb,
            outcome: "mcp_auth_required".to_owned(),
            reason_codes: Vec::new(),
        })
    );

    run.door
        .closed
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

/// Review repro (Sol R6, #1405): a door refused a resumed write's kept answer
/// but admitted fresh writes, and the guest caught the refusal and made the
/// write again. The retry counted the refused write as made, took the next
/// receipt, and committed a second task. A write past a refused kept answer
/// now gets that refusal too, and the vault keeps its one write.
#[test]
fn a_retry_past_a_refused_kept_answer_writes_nothing() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    run.stop_after(vec![create_task()]);

    run.door
        .refuses_kept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut retried = resumed_step(vec![create_task(), create_task()]);
    let outcome = run.resume(&run.config, &mut retried);
    assert!(
        matches!(
            outcome,
            Err(EngineExecutorError::Engine(Error::InvariantViolation(_)))
        ),
        "a step whose write was refused does not close: {outcome:?}"
    );
    let refused = SelfDispatchOutcome::Denied(crate::code_run::SelfDeniedResult {
        effect: SelfEffect::AgentVerb,
        outcome: "read_refused".to_owned(),
        reason_codes: Vec::new(),
    });
    assert_eq!(retried.answers, vec![refused.clone(), refused]);
}

/// Review repro (Sol R8, #1405): past a resumed write whose kept answer the
/// door refused, the guest spoke, and the bubble committed although the step
/// could no longer close. Every call past such a write now gets its refusal,
/// so nothing more commits.
#[test]
fn a_bubble_past_a_refused_kept_answer_speaks_nothing() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    run.stop_after(vec![create_task()]);
    let messages = || {
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len()
    };
    let before = messages();

    run.door
        .refuses_kept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut spoke = resumed_step(vec![
        create_task(),
        SelfCall::Speak(SelfSpeechCall::new("still here")),
    ]);
    let outcome = run.resume(&run.config, &mut spoke);
    assert!(
        matches!(
            outcome,
            Err(EngineExecutorError::Engine(Error::InvariantViolation(_)))
        ),
        "a step whose write was refused does not close: {outcome:?}"
    );
    assert_eq!(messages(), before, "nothing is spoken past the refusal");
    assert_eq!(
        spoke.answers.pop().expect("the bubble's answer"),
        SelfDispatchOutcome::Denied(crate::code_run::SelfDeniedResult {
            effect: SelfEffect::Speak,
            outcome: "read_refused".to_owned(),
            reason_codes: Vec::new(),
        })
    );
}

/// The guest's answer to a call the door refused with `code`.
fn refused_as(effect: SelfEffect, code: &str) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Denied(crate::code_run::SelfDeniedResult {
        effect,
        outcome: code.to_owned(),
        reason_codes: Vec::new(),
    })
}

/// Review repro (Astra, #1405 re-check): a refused kept answer kept its step
/// from closing, but only the attempt that got it knew. The next attempt of
/// the same step started with an empty history, and its bubble committed
/// before the unmet receipt stopped the checkpoint. The refusal now stands on
/// the receipt: every attempt of the step gets it until an admitted read
/// reconciles the receipt, and the step then closes with its one task.
#[test]
fn a_refused_kept_answer_holds_in_the_steps_next_attempt() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    let first = run.stop_after(vec![create_task()]);
    let messages = || {
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len()
    };
    let before = messages();
    let speak = || SelfCall::Speak(SelfSpeechCall::new("still here"));
    let not_closed = |outcome: EngineExecutorResult<EngineExecutorOutcome>| {
        assert!(
            matches!(
                outcome,
                Err(EngineExecutorError::Engine(Error::InvariantViolation(_)))
            ),
            "a step whose write was refused does not close: {outcome:?}"
        );
    };

    run.door
        .refuses_kept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut refused = resumed_step(vec![create_task()]);
    not_closed(run.resume(&run.config, &mut refused));
    assert_eq!(
        refused.answers,
        vec![refused_as(SelfEffect::AgentVerb, "read_refused")]
    );

    let mut next = resumed_step(vec![speak(), create_task()]);
    not_closed(run.resume(&run.config, &mut next));
    assert_eq!(messages(), before, "the next attempt speaks nothing");
    assert_eq!(
        next.answers,
        vec![
            refused_as(SelfEffect::Speak, "read_refused"),
            refused_as(SelfEffect::AgentVerb, "read_refused"),
        ]
    );

    run.door
        .refuses_kept
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut admitted = resumed_step(vec![create_task(), speak()]);
    let outcome = run.resume(&run.config, &mut admitted);
    assert_eq!(
        outcome.expect("the admitted attempt").status,
        EngineExecutorStatus::Complete
    );
    assert_eq!(
        admitted.answers.first(),
        Some(&first),
        "the admitted attempt answers with the first receipt"
    );
    assert_eq!(messages(), before + 1, "the reconciled step speaks again");
}

/// A kept answer's refusal spelled as a gate's own word stands on its receipt
/// as that gate's rejection: the step's next attempt halts its bridge at its
/// first call, as after any gate's, and so cannot close on a later admitted
/// read. The attempt after it reconciles the receipt and closes.
#[test]
fn a_kept_answer_refused_in_a_gate_word_halts_the_next_attempt() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    let first = run.stop_after(vec![create_task()]);
    let speak = || SelfCall::Speak(SelfSpeechCall::new("still here"));

    run.door
        .refuses_kept_as_a_gate
        .store(true, std::sync::atomic::Ordering::SeqCst);
    run.door
        .refuses_kept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut refused = resumed_step(vec![create_task()]);
    assert!(run.resume(&run.config, &mut refused).is_err());
    assert_eq!(
        refused.answers,
        vec![refused_as(SelfEffect::AgentVerb, "deny")]
    );

    run.door
        .refuses_kept
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut next = resumed_step(vec![speak(), create_task()]);
    assert!(run.resume(&run.config, &mut next).is_err());
    assert_eq!(
        next.answers,
        vec![
            refused_as(SelfEffect::Speak, "deny"),
            SelfDispatchOutcome::Failed(crate::code_run::SelfFailedResult {
                effect: SelfEffect::AgentVerb,
                error: "host_bridge_halted".to_owned(),
            }),
        ]
    );

    let mut admitted = resumed_step(vec![create_task()]);
    let outcome = run.resume(&run.config, &mut admitted);
    assert_eq!(
        outcome.expect("the admitted attempt").status,
        EngineExecutorStatus::Complete
    );
    assert_eq!(admitted.answers, vec![first]);
}

/// A host door that admits a run's own calls until it closes, as a connector
/// credential stops admitting them once it is revoked.
struct ClosingDoor {
    closed: std::sync::atomic::AtomicBool,
}

impl ClosingDoor {
    fn new(closed: bool) -> Arc<Self> {
        Arc::new(Self {
            closed: std::sync::atomic::AtomicBool::new(closed),
        })
    }

    fn set_closed(&self, closed: bool) {
        self.closed
            .store(closed, std::sync::atomic::Ordering::SeqCst);
    }
}

impl AgentVerbDoor for ClosingDoor {
    fn call(
        &self,
        _: &SelfAgentVerbCall,
        _: &HostWriteOrigin,
        _: crate::runtime_hooks::InvocationId,
    ) -> crate::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(AgentVerbRefusal {
            code: crate::code_run::AGENT_VERB_DOOR_UNBOUND.to_owned(),
        }))
    }

    fn admit_run_call(
        &self,
        _: RunCall,
    ) -> std::result::Result<Option<crate::claim::ScopedReadActorKey>, AgentVerbRefusal> {
        if self.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(AgentVerbRefusal {
                code: "door_closed".to_owned(),
            });
        }
        Ok(None)
    }
}

const RECORDED_OBSERVATION: &str = "the heron lantern hangs by the north gate";

/// Step 0 records an observation. Step 1 reads it back through its context
/// reference, closes the door, and reads it again.
struct ReadsBackItsOutput {
    door: Arc<ClosingDoor>,
    steps: u64,
    reads: Vec<Result<Option<Vec<u8>>>>,
}

impl JsCodeModeRuntime for ReadsBackItsOutput {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        self.steps += 1;
        if self.steps == 1 {
            return Ok(JsCodeModeStepOutcome::pending(RECORDED_OBSERVATION));
        }
        let path = super::super::store::recoverable_chunk_path(
            0,
            crate::compaction::output::OutputRef::from_bytes(RECORDED_OBSERVATION.as_bytes()),
            0,
        );
        self.reads.push(host.read_recoverable_output(&path));
        self.door.set_closed(true);
        self.reads.push(host.read_recoverable_output(&path));
        Ok(JsCodeModeStepOutcome::complete(""))
    }
}

/// Review repro (Sol, burn engine-prs-03 R1): a run read its own recorded
/// output back after its door stopped admitting it, though every bridge call
/// was refused. The read is a call the run serves itself: the door rules on
/// it too.
#[test]
fn a_closed_door_ends_a_runs_reads_of_its_recorded_output() {
    let (_dir, vault) = open_test_vault();
    let door = ClosingDoor::new(false);
    let gated =
        gated_actor_write(&vault, "run-recorded-output-door").with_agent_verb_door(door.clone());
    let config = executor_config(
        entity(0xE8),
        EngineExecutorLimits {
            soft_steps: 4,
            hard_steps: 8,
        },
    );
    let backend = FixtureBackend::new(["const first = 1;", "const second = 2;"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = ReadsBackItsOutput {
        door,
        steps: 0,
        reads: Vec::new(),
    };
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
    let _ = block_on_ready(executor.run(&config));
    drop(executor);
    let [open, closed] = runtime.reads.as_slice() else {
        panic!("step 1 read twice: {:?}", runtime.reads);
    };
    let read = open
        .as_ref()
        .expect("the open door's read")
        .as_deref()
        .expect("the recorded output");
    assert!(
        String::from_utf8_lossy(read).contains("north gate"),
        "fixture check: the reference names the recorded observation"
    );
    let refused = closed
        .as_ref()
        .expect_err("the closed door's read is refused");
    assert!(refused.to_string().contains("door_closed"), "{refused}");
}

/// Step 0 records a large observation. Step 1 asks for chunks of it by
/// references the path itself shows are wrong, around one good read.
struct ReadsBadReferences {
    steps: u64,
    reads: Vec<(Result<Option<Vec<u8>>>, usize)>,
}

const LARGE_OBSERVATION_BYTES: usize = 2 << 20;

impl JsCodeModeRuntime for ReadsBadReferences {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        use crate::compaction::output::OutputRef;
        use crate::session_overlay::hygiene_tests::peak_allocated;
        self.steps += 1;
        let observation = "n".repeat(LARGE_OBSERVATION_BYTES);
        if self.steps == 1 {
            return Ok(JsCodeModeStepOutcome::pending(observation));
        }
        let source = OutputRef::from_bytes(observation.as_bytes());
        let chunk = |offset| super::super::store::recoverable_chunk_path(0, source, offset);
        let elsewhere = OutputRef {
            hash: [7; 32],
            ..source
        };
        for path in [
            chunk(LARGE_OBSERVATION_BYTES as u64 + 1),
            chunk(0),
            super::super::store::recoverable_chunk_path(0, elsewhere, 0),
        ] {
            self.reads
                .push(peak_allocated(|| host.read_recoverable_output(&path)));
        }
        Ok(JsCodeModeStepOutcome::complete(""))
    }
}

/// F04 H416: a recorded-output read whose path names an offset past its own
/// length, or a source a read already showed it is not, is refused without
/// loading the source. Main loaded and decoded the whole output first.
#[test]
fn a_bad_recorded_output_reference_is_refused_without_loading_the_source() {
    let (_dir, vault) = open_test_vault();
    let gated = gated_actor_write(&vault, "run-bad-output-reference")
        .with_agent_verb_door(ClosingDoor::new(false));
    let config = executor_config(
        entity(0xE9),
        EngineExecutorLimits {
            soft_steps: 4,
            hard_steps: 8,
        },
    );
    let backend = FixtureBackend::new(["const first = 1;", "const second = 2;"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = ReadsBadReferences {
        steps: 0,
        reads: Vec::new(),
    };
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
    let _ = block_on_ready(executor.run(&config));
    drop(executor);
    let [
        (past_end, past_end_peak),
        (good, _),
        (elsewhere, elsewhere_peak),
    ] = runtime.reads.as_slice()
    else {
        panic!("step 1 read three times: {:?}", runtime.reads);
    };
    let good = good
        .as_ref()
        .expect("the good read")
        .as_deref()
        .expect("the recorded output");
    assert_eq!(
        good.len(),
        super::super::store::RECOVERABLE_OUTPUT_CHUNK_BYTES
    );
    for (refused, peak) in [(past_end, past_end_peak), (elsewhere, elsewhere_peak)] {
        assert!(refused.is_err(), "{refused:?}");
        assert!(
            *peak < LARGE_OBSERVATION_BYTES / 4,
            "refused after holding {peak} bytes"
        );
    }
}

/// Review repro (Sol, burn engine-prs-03 R1): a run whose door stopped
/// admitting its calls still spoke its answer, through the executor's
/// trailing implicit speech. That bubble is the run's own `self.speak`: a
/// closed door refuses it, typed, and the checkpointed intent is delivered by
/// a later run the door admits.
#[test]
fn a_closed_door_speaks_no_trailing_bubble_until_it_opens() {
    let (_dir, vault) = open_test_vault();
    let door = ClosingDoor::new(true);
    let gated =
        gated_actor_write(&vault, "run-trailing-speech-door").with_agent_verb_door(door.clone());
    let config = executor_config(entity(0xE9), EngineExecutorLimits::default());
    let backend =
        FixtureBackend::new(["```js\nconst done = true;\n```\nThe amber kettle is warm."]);
    let lease = BudgetLease::for_test("executor-lease");
    let messages = || {
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len()
    };
    let before = messages();

    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("runtime done")]);
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
    let refused = block_on_ready(executor.run(&config)).expect_err("the bubble is refused");
    drop(executor);
    assert!(
        matches!(&refused, EngineExecutorError::HostRefused { code } if code == "door_closed"),
        "{refused}"
    );
    assert_eq!(messages(), before, "a closed door speaks nothing");

    door.set_closed(false);
    let mut runtime = FixtureRuntime::new(Vec::new());
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
    let outcome = block_on_ready(executor.run(&config)).expect("the admitted retry");
    drop(executor);
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(messages(), before + 1, "the retry delivers the kept intent");
}

/// A custom host door that refuses a run's search with a gate's own outcome
/// word, `deny`, and admits the run's other calls.
struct GateWordDoor;

impl AgentVerbDoor for GateWordDoor {
    fn call(
        &self,
        _: &SelfAgentVerbCall,
        _: &HostWriteOrigin,
        _: crate::runtime_hooks::InvocationId,
    ) -> crate::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        Ok(Err(AgentVerbRefusal {
            code: crate::code_run::AGENT_VERB_DOOR_UNBOUND.to_owned(),
        }))
    }

    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> std::result::Result<Option<crate::claim::ScopedReadActorKey>, AgentVerbRefusal> {
        if call == RunCall::Bridge(SelfEffect::MemorySearch) {
            return Err(AgentVerbRefusal {
                code: "deny".to_owned(),
            });
        }
        Ok(None)
    }
}

/// One step whose guest catches each refused call and goes on, as a QuickJS
/// guest catches `host_call_refused`.
struct CatchingStep {
    calls: Vec<SelfCall>,
}

impl JsCodeModeRuntime for CatchingStep {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        for call in self.calls.clone() {
            let _caught = host.dispatch_self(call);
        }
        Ok(JsCodeModeStepOutcome::complete(""))
    }
}

/// Review repro (Sol R3, burn engine-prs-03): a door refused a run's search
/// with `deny`, a gate's own outcome word. The host failed that call without
/// recording it, the guest caught the failure and spoke, and the bubble
/// committed one bridge position past a gap, so its step could not keep its
/// checkpoint. A door's `deny` is now the gate's refusal: recorded where it
/// fell, and the bridge halts after it as after any gate's.
#[test]
fn a_door_refusal_spelled_as_a_gate_word_halts_the_bridge_as_a_gate_does() {
    let (_dir, vault) = open_test_vault();
    let gated = gated_actor_write(&vault, "run-gate-word-door")
        .with_agent_verb_door(Arc::new(GateWordDoor));
    let config = executor_config(entity(0xEA), EngineExecutorLimits::default());
    let backend = FixtureBackend::new(["await self.memory.search({query: 'heron lantern'});"]);
    let lease = BudgetLease::for_test("executor-lease");
    let messages = || {
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len()
    };
    let before = messages();
    let mut step = CatchingStep {
        calls: vec![
            SelfCall::MemorySearch(SelfMemorySearchCall::new("heron lantern", 4)),
            SelfCall::Speak(SelfSpeechCall::new("still here")),
        ],
    };

    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut step, &gated);
    let failed = block_on_ready(executor.run(&config)).expect_err("the step fails on the refusal");
    drop(executor);
    assert!(
        matches!(
            &failed,
            EngineExecutorError::Engine(Error::Gate(GateError::GateWriteRejected {
                outcome: "deny",
                ..
            }))
        ),
        "{failed}"
    );
    assert_eq!(messages(), before, "nothing is spoken past the refusal");
    let record = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("read the run's record")
        .expect("the run's record");
    assert_eq!(
        record
            .bridge_calls
            .iter()
            .map(|call| (call.seq, call.effect.as_str(), bridge_outcome_kind(call)))
            .collect::<Vec<_>>(),
        vec![
            (0, "self.memory.search", "denied"),
            (1, "self.speak", "failed")
        ]
    );
}

/// What step 1 of a [`ScriptedRun`] does, in order.
#[derive(Clone)]
enum Act {
    /// Makes this bridge call. The guest catches a failed call and goes on.
    Call(SelfCall),
    /// The door admits kept answers again, as a door may change its ruling
    /// between two calls.
    Reopen,
    /// Reads step 0's observation back through its context reference.
    ReadBack,
}

/// Step 0 records an observation and step 1 does its acts. One that `stops`
/// halts the process after its acts, before the step's checkpoint.
struct ScriptedRun {
    door: Option<Arc<TaskCreateDoor>>,
    acts: Vec<Act>,
    stops: bool,
    answers: Vec<Result<SelfDispatchOutcome>>,
    reads: Vec<Result<Option<Vec<u8>>>>,
}

impl ScriptedRun {
    fn new(door: Option<&Arc<TaskCreateDoor>>, acts: Vec<Act>) -> Self {
        Self {
            door: door.cloned(),
            acts,
            stops: false,
            answers: Vec::new(),
            reads: Vec::new(),
        }
    }
}

impl JsCodeModeRuntime for ScriptedRun {
    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        if step.seq == 0 {
            return Ok(JsCodeModeStepOutcome::pending(RECORDED_OBSERVATION));
        }
        for act in self.acts.clone() {
            match act {
                Act::Call(call) => self
                    .answers
                    .push(host.dispatch_self(call).map(|response| response.outcome)),
                Act::Reopen => {
                    if let Some(door) = &self.door {
                        door.refuses_kept
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                    }
                }
                Act::ReadBack => {
                    let path = super::super::store::recoverable_chunk_path(
                        0,
                        crate::compaction::output::OutputRef::from_bytes(
                            RECORDED_OBSERVATION.as_bytes(),
                        ),
                        0,
                    );
                    self.reads.push(host.read_recoverable_output(&path));
                }
            }
        }
        assert!(
            !self.stops,
            "the process stops before the step's checkpoint"
        );
        Ok(JsCodeModeStepOutcome::complete(""))
    }
}

/// The run's step 0 records an observation; its step 1 commits `tasks.create`
/// and the process stops before that step's checkpoint.
fn observe_then_stop_after_a_write(run: &VerbWriteRun<'_>) {
    let mut first = ScriptedRun {
        stops: true,
        ..ScriptedRun::new(None, vec![Act::Call(create_task())])
    };
    assert!(
        run.run(&run.config, &mut first).is_err(),
        "the process stopped"
    );
    assert!(
        matches!(
            first.answers.as_slice(),
            [Ok(SelfDispatchOutcome::AgentVerb(_))]
        ),
        "the first attempt's write committed: {:?}",
        first.answers
    );
}

/// The one read a step made, which must have been refused with `code`.
fn assert_read_refused(reads: &[Result<Option<Vec<u8>>>], code: &str) {
    let [read] = reads else {
        panic!("step 1 read once: {reads:?}");
    };
    let refused = read.as_ref().expect_err("the read is refused");
    assert!(refused.to_string().contains(code), "{refused}");
}

/// Review repro (Sol R9, #1405): past a resumed write whose kept answer the
/// door refused, the guest read an earlier step's recorded output back. The
/// read is a host import, not a bridge call, so it skipped the check that
/// refuses every call past such a write; the door, asked again, admitted it,
/// and the guest got the bytes although its step could no longer close. The
/// read now gets that write's refusal before any bytes load.
#[test]
fn a_recorded_read_past_a_refused_kept_answer_reads_nothing() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    observe_then_stop_after_a_write(&run);

    run.door
        .refuses_kept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut resumed = ScriptedRun::new(
        Some(&run.door),
        vec![Act::Call(create_task()), Act::Reopen, Act::ReadBack],
    );
    let outcome = run.resume(&run.config, &mut resumed);
    assert!(
        matches!(
            outcome,
            Err(EngineExecutorError::Engine(Error::InvariantViolation(_)))
        ),
        "a step whose write was refused does not close: {outcome:?}"
    );
    assert!(
        matches!(
            resumed.answers.as_slice(),
            [Ok(answer)] if *answer == refused_as(SelfEffect::AgentVerb, "read_refused")
        ),
        "{:?}",
        resumed.answers
    );
    assert_read_refused(&resumed.reads, "read_refused");
}

/// Review repro (Sol R9, #1405), the halt half: a door's `deny` halts the
/// bridge, and a recorded-output read after it is refused as a bridge call
/// there is, though the door admits recorded reads.
#[test]
fn a_recorded_read_past_a_halted_bridge_reads_nothing() {
    let (_dir, vault) = open_test_vault();
    let gated = gated_actor_write(&vault, "run-halted-recorded-read")
        .with_agent_verb_door(Arc::new(GateWordDoor));
    let config = executor_config(entity(0xEB), EngineExecutorLimits::default());
    let backend = FixtureBackend::new([
        "const first = 1;",
        "await self.memory.search({query: 'heron lantern'});",
    ]);
    let lease = BudgetLease::for_test("executor-lease");
    let search = SelfCall::MemorySearch(SelfMemorySearchCall::new("heron lantern", 4));
    let mut runtime = ScriptedRun::new(None, vec![Act::Call(search), Act::ReadBack]);
    let mut executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated);
    let failed = block_on_ready(executor.run(&config)).expect_err("the step fails on the refusal");
    drop(executor);
    assert!(
        matches!(
            &failed,
            EngineExecutorError::Engine(Error::Gate(GateError::GateWriteRejected {
                outcome: "deny",
                ..
            }))
        ),
        "{failed}"
    );
    assert_read_refused(&runtime.reads, "host_bridge_halted");
}

/// Review repro (Sol R10, #1405): a kept answer's refusal spelled as a gate's
/// word stood on its receipt, but a recorded-output read that met it got a
/// catchable error and left the bridge running. The guest caught it, made
/// the write again through a door that now admitted it, spoke, and closed
/// the step. Such a read now halts the bridge as a gate's rejection does.
#[test]
fn a_recorded_read_of_a_gate_word_refusal_halts_the_bridge() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    observe_then_stop_after_a_write(&run);
    let messages = || {
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len()
    };
    let before = messages();

    run.door
        .refuses_kept_as_a_gate
        .store(true, std::sync::atomic::Ordering::SeqCst);
    run.door
        .refuses_kept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        run.resume(&run.config, &mut resumed_step(vec![create_task()]))
            .is_err()
    );

    let speak = SelfCall::Speak(SelfSpeechCall::new("still here"));
    let mut next = ScriptedRun::new(
        Some(&run.door),
        vec![
            Act::Reopen,
            Act::ReadBack,
            Act::Call(create_task()),
            Act::Call(speak),
        ],
    );
    assert!(run.resume(&run.config, &mut next).is_err());
    assert_read_refused(&next.reads, "deny");
    let halted = |effect| {
        SelfDispatchOutcome::Failed(crate::code_run::SelfFailedResult {
            effect,
            error: "host_bridge_halted".to_owned(),
        })
    };
    assert!(
        matches!(
            next.answers.as_slice(),
            [Ok(write), Ok(bubble)]
                if *write == halted(SelfEffect::AgentVerb) && *bubble == halted(SelfEffect::Speak)
        ),
        "{:?}",
        next.answers
    );
    assert_eq!(messages(), before, "nothing is spoken past the halt");
}

/// Review repro (Sol R10, #1405): a fresh write the door refused keeps that
/// refusal as its answer. Resumed, the door refused reading it back with the
/// same code, and the step closed: its write row matched the kept refusal,
/// though no admitted read had reconciled the receipt. A receipt whose kept
/// answer stands refused is not met, so the step does not close until an
/// admitted read reconciles it.
#[test]
fn a_kept_refusal_refused_again_does_not_close_its_step() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    run.door
        .closed
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let mut first = RecordedStep {
        calls: vec![create_task()],
        stops: true,
        answers: Vec::new(),
    };
    assert!(
        run.run(&run.config, &mut first).is_err(),
        "the process stopped"
    );
    let refused = refused_as(SelfEffect::AgentVerb, "mcp_auth_required");
    assert_eq!(first.answers, vec![refused.clone()]);

    let mut again = resumed_step(vec![create_task()]);
    let outcome = run.resume(&run.config, &mut again);
    assert!(
        matches!(
            outcome,
            Err(EngineExecutorError::Engine(Error::InvariantViolation(_)))
        ),
        "a step whose kept answer stands refused does not close: {outcome:?}"
    );
    assert_eq!(again.answers, vec![refused.clone()]);

    run.door
        .closed
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut admitted = resumed_step(vec![create_task()]);
    let outcome = run.resume(&run.config, &mut admitted);
    assert_eq!(
        outcome.expect("the admitted attempt").status,
        EngineExecutorStatus::Complete
    );
    assert_eq!(admitted.answers, vec![refused]);
}

/// Review repro (Sol R10, #1405): a ruling on a kept answer replaced the one
/// before it, and the receipt's generation counts rows, not their content.
/// An attempt that loaded a refused receipt and was admitted cleared it
/// although another attempt had refused the answer again meanwhile. Every
/// ruling now appends, so the stale admission fails its compare and the
/// newer refusal stands.
#[test]
fn a_ruling_on_an_older_receipt_does_not_clear_a_newer_refusal() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    let first = run.stop_after(vec![create_task()]);
    let messages = || {
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len()
    };
    let before = messages();
    run.door
        .refuses_kept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        run.resume(&run.config, &mut resumed_step(vec![create_task()]))
            .is_err()
    );

    // While the door rules on this attempt's kept read, another attempt of
    // the same step has its own kept read refused.
    run.door
        .refuses_kept
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let (shared, actor) = (Arc::clone(&vault), run.door.actor);
    *run.door.on_kept_read.lock().expect("kept-read hook") = Some(Box::new(move || {
        let door = TaskCreateDoor::new(&shared, actor, serde_json::Map::new());
        door.refuses_kept
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let other = VerbWriteRun::through(&shared, door);
        let refused = other.run(&other.config, &mut resumed_step(vec![create_task()]));
        assert!(
            matches!(refused, Ok(Err(_))),
            "the other attempt is refused"
        );
    }));
    let stale = run.resume(&run.config, &mut resumed_step(vec![create_task()]));
    assert!(
        matches!(
            stale,
            Err(EngineExecutorError::Engine(Error::ConcurrentWrite(_)))
        ),
        "the admission decided on the older receipt fails: {stale:?}"
    );

    run.door
        .refuses_kept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let speak = SelfCall::Speak(SelfSpeechCall::new("still here"));
    let mut next = resumed_step(vec![speak, create_task()]);
    assert!(run.resume(&run.config, &mut next).is_err());
    assert_eq!(messages(), before, "the newer refusal still stands");

    run.door
        .refuses_kept
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let mut admitted = resumed_step(vec![create_task()]);
    let outcome = run.resume(&run.config, &mut admitted);
    assert_eq!(
        outcome.expect("the admitted attempt").status,
        EngineExecutorStatus::Complete
    );
    assert_eq!(admitted.answers, vec![first]);
}

/// A resumed write that changed its input fails as a host fault: the bridge
/// keeps no row for it, so its step can never checkpoint a later row. The
/// guest caught that fault and spoke, and the bubble committed. The bridge
/// now halts after any call it could not record.
#[test]
fn a_call_the_bridge_could_not_record_halts_it() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let run = VerbWriteRun::new(&vault);
    run.stop_after(vec![create_task()]);
    let messages = || {
        vault
            .entities_by_type(crate::registry::ENTITY_TYPE_MESSAGE)
            .expect("messages")
            .len()
    };
    let before = messages();
    let changed = SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: AgentVerb::TasksCreate,
        input: serde_json::json!({"spec": "summarize the open notes"}),
    });
    let mut caught = CatchingStep {
        calls: vec![changed, SelfCall::Speak(SelfSpeechCall::new("still here"))],
    };
    assert!(run.resume(&run.config, &mut caught).is_err());
    assert_eq!(messages(), before, "nothing is spoken past the fault");
}

/// Removes the run's agent from its room, then makes `calls`, catching each
/// failure as a guest does, and keeps what each call answered.
struct RemovedMidStep<'v> {
    vault: &'v Vault,
    room: EntityId,
    agent: EntityId,
    by: WriteActor,
    calls: Vec<SelfCall>,
    answers: Vec<Result<SelfDispatchResponse>>,
}

impl JsCodeModeRuntime for RemovedMidStep<'_> {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        self.vault
            .leave_member(self.room, self.agent, self.by, 50)
            .expect("the owner removes the agent");
        for call in self.calls.clone() {
            self.answers.push(host.dispatch_self(call));
        }
        Ok(JsCodeModeStepOutcome::complete(""))
    }
}

/// Review repro (Sol R13, merging #1406): a room-bound run's agent was
/// removed mid-step. Its search was refused `NotInRoom`, a refusal the bridge
/// keeps no row for, so the bridge halted. The guest caught it and searched
/// again, and the halt answered `Failed(host_bridge_halted)` without asking
/// the room, where the run alone would have heard `NotInRoom` again. The
/// bridge's answers past a halt or a wait now check the participant first.
#[test]
fn a_removed_agents_run_hears_not_in_room_past_its_halted_bridge() {
    use crate::conversation::{ConversationBody, HistoryChoice};
    use crate::error::OffRecordError;
    use crate::off_record::OffRecordBackendClass;

    let (_dir, vault) = open_test_vault();
    let owner = vault.ensure_embedded_owner_actor().expect("owner");
    let by = WriteActor::new(owner, EdgeActorClass::Human);
    let agent = seed_person(&vault, 0xE7);
    let room = EntityId::now();
    vault
        .create_conversation(room, &ConversationBody::default(), by, 1)
        .expect("room");
    for (at, member) in [(2, owner), (3, agent)] {
        vault
            .join_member(room, member, by, at, HistoryChoice::Share)
            .expect("join the room");
    }
    let session = vault
        .off_record_session_vault()
        .enter_in_room("halted-room", OffRecordBackendClass::Local, room, owner)
        .expect("start off record");
    let gated = GatedActorWrite::for_off_record_session(
        &session,
        WriteActor::new(agent, EdgeActorClass::Agent),
        "run-halted-room",
    )
    .expect("bind the run");
    let backend = FixtureBackend::new(["await self.memory.search({query: 'heron lantern'});"]);
    let lease = BudgetLease::for_test("executor-lease");
    let config = executor_config(entity(0xE8), EngineExecutorLimits::default());
    let search = || SelfCall::MemorySearch(SelfMemorySearchCall::new("heron lantern", 4));
    let mut step = RemovedMidStep {
        vault: &vault,
        room,
        agent,
        by,
        calls: vec![search(), search()],
        answers: Vec::new(),
    };
    let ended = {
        let mut executor = EngineNativeExecutor::for_off_record_session(
            &session, &backend, &lease, &mut step, &gated,
        )
        .expect("bind the executor");
        block_on_ready(executor.run(&config)).map(|outcome| outcome.status)
    };
    assert!(ended.is_err(), "{ended:?}");
    let not_in_room = |answer: &Result<SelfDispatchResponse>| {
        matches!(
            answer,
            Err(Error::OffRecord(OffRecordError::OffRecordNotInRoom { actor_ref, .. }))
                if *actor_ref == agent.to_hex()
        )
    };
    assert!(step.answers.iter().all(not_in_room), "{:?}", step.answers);
    assert_eq!(step.answers.len(), 2);
}
