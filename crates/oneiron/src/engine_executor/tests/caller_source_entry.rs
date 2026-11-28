use std::sync::Arc;

use super::*;
use crate::code_run::{
    AgentVerbAnswer, AgentVerbDoor, AgentVerbRefusal, RunCall, SelfAgentVerbCall, WaitDeliveries,
};
use crate::memory::HostWriteOrigin;
use crate::session_overlay::RouteTarget;
use crate::task_verb::sdk::{AgentVerb, TaskCreateRequest};
use oneiron_contracts::fingerprint::{ContentHash, LegacyDigest, purposes};

/// The caller's program, as written: one write.
const WRITE_CODE: &str = "await self.memory.tasks.create({spec: 'summarize the open notes'});";

/// Another program: other bytes under the same run.
const OTHER_CODE: &str = "await self.memory.tasks.create({spec: 'draft the launch note'});";

/// Caller source with a settled write before the wait.
const ASK_CODE: &str = concat!(
    "await self.memory.tasks.create({spec: 'summarize the open notes'});\n",
    "const answer = await self.ask('continue?');",
);

/// A host's verb door reduced to the one verb a source test calls:
/// `tasks.create` on the host's memory surface, under the origin the
/// dispatcher hands it. It admits every call, or refuses the run's reads of
/// its recorded outputs as a gate does: these tests pin the source entry,
/// not the door.
struct TaskCreateDoor {
    vault: Arc<Vault>,
    actor: WriteActor,
    refuses_recorded_reads: bool,
}

impl AgentVerbDoor for TaskCreateDoor {
    fn call(
        &self,
        call: &SelfAgentVerbCall,
        origin: &HostWriteOrigin,
        _: crate::runtime_hooks::InvocationId,
    ) -> crate::Result<std::result::Result<AgentVerbAnswer, AgentVerbRefusal>> {
        let refused = || AgentVerbRefusal {
            code: "engine_error".to_owned(),
            hook_notice: None,
            reason_codes: Vec::new(),
        };
        let Ok(input) = serde_json::from_value::<TaskCreateRequest>(call.input.clone()) else {
            return Ok(Err(refused()));
        };
        let memory = self
            .vault
            .memory(self.actor.entity_ref(), self.actor.actor_class())
            .with_host_origin(origin.clone());
        let Ok(receipt) = crate::task_verb::sdk::tasks_create(&memory, input) else {
            return Ok(Err(refused()));
        };
        let Ok(output) = serde_json::to_value(receipt) else {
            return Ok(Err(refused()));
        };
        Ok(Ok(AgentVerbAnswer {
            output,
            rows: Some(Vec::new()),
            hook_notice: None,
            observations: Vec::new(),
            hooks: Vec::new(),
            stored_output: None,
        }))
    }

    fn admit_run_call(
        &self,
        call: RunCall,
    ) -> std::result::Result<Option<crate::claim::ScopedReadActorKey>, AgentVerbRefusal> {
        if self.refuses_recorded_reads && call == RunCall::RecordedOutput {
            return Err(AgentVerbRefusal {
                code: "deny".to_owned(),
                hook_notice: None,
                reason_codes: Vec::new(),
            });
        }
        Ok(None)
    }
}

/// One source program's scripted run: it dispatches `calls` through the
/// host and answers `outcome`. `seen` keeps the scripts it ran, so a
/// re-entry that must run nothing asserts it ran none; `answers` keeps
/// what each call came back with. One that reads a recorded output after
/// its calls keeps whether the read was refused.
struct SourceStep {
    calls: Vec<SelfCall>,
    outcome: JsCodeModeStepOutcome,
    seen: Vec<String>,
    answers: Vec<SelfDispatchOutcome>,
    reads_recorded_output: bool,
    read_refused: Option<bool>,
}

impl SourceStep {
    fn new(calls: Vec<SelfCall>, outcome: JsCodeModeStepOutcome) -> Self {
        Self {
            calls,
            outcome,
            seen: Vec::new(),
            answers: Vec::new(),
            reads_recorded_output: false,
            read_refused: None,
        }
    }

    fn reading_a_recorded_output(self) -> Self {
        Self {
            reads_recorded_output: true,
            ..self
        }
    }
}

impl JsCodeModeRuntime for SourceStep {
    fn run_step(
        &mut self,
        step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        self.seen.push(step.script.to_owned());
        for call in self.calls.clone() {
            self.answers.push(host.dispatch_self(call)?.outcome);
        }
        if self.reads_recorded_output {
            let read = host.read_recoverable_output(&observation_output_path(0));
            self.read_refused = Some(read.is_err());
        }
        Ok(self.outcome.clone())
    }
}

/// A vault whose verb door serves `tasks.create`, as a source run's host
/// binds it.
struct SourceHarness<'a> {
    vault: &'a Vault,
    gated_write: GatedActorWrite<'a>,
}

impl<'a> SourceHarness<'a> {
    fn new(vault: &'a Arc<Vault>) -> Self {
        Self::with_door(vault, false)
    }

    /// A harness whose door refuses the run's reads of its recorded outputs
    /// as a gate does.
    fn refusing_recorded_reads(vault: &'a Arc<Vault>) -> Self {
        Self::with_door(vault, true)
    }

    fn with_door(vault: &'a Arc<Vault>, refuses_recorded_reads: bool) -> Self {
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
        let door = Arc::new(TaskCreateDoor {
            vault: Arc::clone(vault),
            actor,
            refuses_recorded_reads,
        });
        let gated_write = GatedActorWrite::new(vault, door.actor, "caller-source-run")
            .expect("gated actor write")
            .with_agent_verb_door(door);
        Self { vault, gated_write }
    }

    /// Enters `config`'s run with the caller's `code` under the no-model
    /// backend (FIX EXECUTE-CALLER-CODE).
    fn enter(
        &self,
        config: &EngineExecutorConfig,
        code: &str,
        runtime: &mut dyn JsCodeModeRuntime,
    ) -> EngineExecutorResult<EngineExecutorOutcome> {
        let backend = NoModelBackend;
        let lease = BudgetLease::for_test("caller-source-lease");
        let mut executor =
            EngineNativeExecutor::new(self.vault, &backend, &lease, runtime, &self.gated_write);
        executor.run_caller_source(config, code)
    }
}

/// A source config for `run_id`'s run of the caller's `code`: its digest
/// binds the exact bytes (FIX EXECUTE-CALLER-CODE). It names a prompt
/// package that is not there, because the source entry never resolves one.
fn source_config(run_id: EntityId, code: &str) -> EngineExecutorConfig {
    let config = EngineExecutorConfig::caller_source(
        run_id,
        determinism(),
        EngineExecutorLimits::default(),
        ContentHash::of(code.as_bytes()),
    );
    EngineExecutorConfig {
        prompt_package_root: std::path::PathBuf::from("caller-source-test-has-no-prompt-package"),
        ..config
    }
}

fn create_task() -> SelfCall {
    SelfCall::AgentVerb(SelfAgentVerbCall {
        verb: AgentVerb::TasksCreate,
        input: serde_json::json!({"spec": "summarize the open notes", "label": null}),
    })
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

/// The TASK and CLAIM rows written since `seeded`, the rows the vault held
/// before the test ran (`Vault::open` seeds 44 claims; one `tasks.create`
/// writes the task and its owner fact, two TASK rows).
fn count_new_tasks_and_claims(vault: &Vault, seeded: &[EntityId]) -> usize {
    written_tasks_and_claims(vault)
        .into_iter()
        .filter(|id| !seeded.contains(id))
        .count()
}

#[test]
fn a_source_run_needs_no_model() {
    let (_dir, vault) = open_test_vault();
    let seeded = written_tasks_and_claims(&vault);
    let vault = Arc::new(vault);
    let harness = SourceHarness::new(&vault);
    let config = source_config(entity(0xC1), WRITE_CODE);
    let mut step = SourceStep::new(
        vec![create_task()],
        JsCodeModeStepOutcome::complete("written"),
    );

    let outcome = harness
        .enter(&config, WRITE_CODE, &mut step)
        .expect("a source run completes");

    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(outcome.steps_run, 1);
    assert_eq!(step.seen, vec![WRITE_CODE.to_owned()]);
    assert_eq!(
        caller_run_input(&vault, config.run_id).expect("read the caller input"),
        Some(CallerRunInput::Source(WRITE_CODE.to_owned())),
    );
    assert_eq!(
        count_new_tasks_and_claims(&vault, &seeded),
        2,
        "the program's one task and its owner fact land"
    );

    // The backend-free constructor runs the same program with no backend
    // bound at all: its completion proves the entry resolves none.
    let backend_free_config = source_config(entity(0xA1), WRITE_CODE);
    let mut backend_free_step = SourceStep::new(
        vec![create_task()],
        JsCodeModeStepOutcome::complete("written"),
    );
    let mut backend_free_executor = EngineNativeExecutor::for_caller_source(
        &vault,
        &mut backend_free_step,
        &harness.gated_write,
    );
    let backend_free_outcome = backend_free_executor
        .run_caller_source(&backend_free_config, WRITE_CODE)
        .expect("the backend-free entry completes");
    assert_eq!(backend_free_outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(
        count_new_tasks_and_claims(&vault, &seeded),
        4,
        "both runs' tasks and owner facts land"
    );
}

#[test]
fn the_same_code_replays_without_writing_again() {
    let (_dir, vault) = open_test_vault();
    let seeded = written_tasks_and_claims(&vault);
    let vault = Arc::new(vault);
    let harness = SourceHarness::new(&vault);
    let run_id = entity(0xC2);
    let config = source_config(run_id, WRITE_CODE);

    let mut first = SourceStep::new(
        vec![create_task()],
        JsCodeModeStepOutcome::complete("written"),
    );
    let first_outcome = harness
        .enter(&config, WRITE_CODE, &mut first)
        .expect("the first entry completes");
    assert_eq!(first_outcome.status, EngineExecutorStatus::Complete);

    let mut second = SourceStep::new(
        vec![create_task()],
        JsCodeModeStepOutcome::complete("written"),
    );
    let second_outcome = harness
        .enter(&config, WRITE_CODE, &mut second)
        .expect("the same code replays");

    assert_eq!(second_outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(
        second_outcome.steps_run, 0,
        "a Complete run runs nothing again"
    );
    assert!(second.seen.is_empty(), "a Complete run runs nothing again");
    assert_eq!(
        second_outcome.replay_record, first_outcome.replay_record,
        "the second entry returns the stored outcome"
    );
    assert_eq!(
        count_new_tasks_and_claims(&vault, &seeded),
        2,
        "the vault holds one new task and its owner fact"
    );
}

#[test]
fn other_code_under_the_same_run_is_refused() {
    let (_dir, vault) = open_test_vault();
    let seeded = written_tasks_and_claims(&vault);
    let vault = Arc::new(vault);
    let harness = SourceHarness::new(&vault);
    let run_id = entity(0xC3);
    let first_config = source_config(run_id, WRITE_CODE);

    let mut first = SourceStep::new(
        vec![create_task()],
        JsCodeModeStepOutcome::complete("written"),
    );
    harness
        .enter(&first_config, WRITE_CODE, &mut first)
        .expect("the first entry completes");
    let committed = vault
        .get_code_run_replay_record(&run_id)
        .expect("read replay")
        .expect("stored replay");
    let written = written_tasks_and_claims(&vault);
    assert_eq!(written.iter().filter(|id| !seeded.contains(id)).count(), 2);

    let second_config = source_config(run_id, OTHER_CODE);
    let mut second = SourceStep::new(
        vec![create_task()],
        JsCodeModeStepOutcome::complete("written"),
    );
    let err = harness
        .enter(&second_config, OTHER_CODE, &mut second)
        .expect_err("other code under the same run is refused");

    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::InvalidConfig(_))
    ));
    assert!(
        err.to_string()
            .contains("engine executor config changed for existing run"),
        "other code fails the run's config check: {err}"
    );
    assert!(second.seen.is_empty(), "the refused entry runs nothing");
    assert_eq!(
        vault
            .get_code_run_replay_record(&run_id)
            .expect("read replay")
            .expect("stored replay"),
        committed,
        "the record is unchanged by the refused entry"
    );
    assert_eq!(
        written_tasks_and_claims(&vault),
        written,
        "the vault is unchanged by the refused entry"
    );
}

#[test]
fn a_delivered_wait_resumes_with_no_model_turn() {
    let (_dir, vault) = open_test_vault();
    let seeded = written_tasks_and_claims(&vault);
    let vault = Arc::new(vault);
    let harness = SourceHarness::new(&vault);
    let run_id = entity(0xC4);
    let config = source_config(run_id, ASK_CODE);

    let mut first = SourceStep::new(
        vec![create_task(), SelfCall::Ask(SelfAskCall::new("continue?"))],
        JsCodeModeStepOutcome::pending("waiting"),
    );
    let first_outcome = harness
        .enter(&config, ASK_CODE, &mut first)
        .expect("the first entry parks");
    let EngineExecutorStatus::Waiting(wait) = &first_outcome.status else {
        panic!("the first entry parks on the ask");
    };
    assert_eq!(first_outcome.steps_run, 1);
    assert_eq!(first_outcome.replay_record.bridge_calls.len(), 2);

    let mut unready = SourceStep::new(Vec::new(), JsCodeModeStepOutcome::complete("must not run"));
    let unready_outcome = harness
        .enter(&config, ASK_CODE, &mut unready)
        .expect("re-park");
    assert_eq!(unready_outcome.status, first_outcome.status);
    assert!(unready.seen.is_empty());
    assert_eq!(
        unready_outcome.replay_record.generation().unwrap(),
        first_outcome.replay_record.generation().unwrap(),
    );

    let delivered = WaitDeliveries::canonical(&vault)
        .deliver(
            wait.wait_id,
            &serde_json::json!({"answer": "go on"}),
            config.determinism.frozen_unix_ms,
        )
        .expect("deliver the reply");
    assert_eq!(delivered, 1, "the reply reaches the parked run");

    let mut diverged = SourceStep::new(
        vec![SelfCall::Ask(SelfAskCall::new("not the settled write"))],
        JsCodeModeStepOutcome::complete("must hold"),
    );
    let err = harness
        .enter(&config, ASK_CODE, &mut diverged)
        .expect_err("a call off the settled prefix holds the run");
    assert!(
        matches!(
            err,
            EngineExecutorError::Engine(Error::Artifact(
                crate::error::ArtifactError::InvalidCodeArtifactBody(_)
            ))
        ),
        "the entry holds as a replay mismatch: {err}"
    );
    assert!(
        err.to_string()
            .contains("the caller source made another call where an earlier entry settled one"),
        "the hold names the caller source, not a pinned entry: {err}"
    );
    assert_eq!(
        diverged.seen.len(),
        1,
        "the diverged entry ran the program once"
    );
    assert_eq!(
        vault.get_code_run_replay_record(&run_id).unwrap().unwrap(),
        first_outcome.replay_record,
        "a replay mismatch does not consume the delivery or change the record",
    );

    let mut second = SourceStep::new(
        vec![create_task(), SelfCall::Ask(SelfAskCall::new("continue?"))],
        JsCodeModeStepOutcome::complete("answered"),
    );
    let second_outcome = harness
        .enter(&config, ASK_CODE, &mut second)
        .expect("the delivered wait resumes");

    assert_eq!(second_outcome.status, EngineExecutorStatus::Complete);
    assert_eq!(second.seen.len(), 1, "the next entry re-runs the program");
    assert_eq!(second.answers.len(), 2);
    let SelfDispatchOutcome::AgentVerb(reply) = &second.answers[1] else {
        panic!("the replayed ask must return the delivered reply");
    };
    assert_eq!(reply.output, serde_json::json!({"answer": "go on"}));
    assert_eq!(count_new_tasks_and_claims(&vault, &seeded), 2);
    assert_eq!(
        second_outcome.replay_record.bridge_calls.len(),
        2,
        "no settled call is issued again"
    );
}

/// A step that failed after it parked returns its wait, as a task step does:
/// the run is parked, its failure is the step's observation, and the entry
/// returns `Waiting`, never the failure (review P1 on #10577).
#[test]
fn a_step_that_fails_after_its_wait_still_parks() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let harness = SourceHarness::refusing_recorded_reads(&vault);
    let run_id = entity(0xC7);
    let config = source_config(run_id, ASK_CODE);

    // The program parks on its ask, then reads a recorded output that the
    // door refuses as a gate: the bridge halts after the wait.
    let mut first = SourceStep::new(
        vec![SelfCall::Ask(SelfAskCall::new("continue?"))],
        JsCodeModeStepOutcome::pending("waiting"),
    )
    .reading_a_recorded_output();
    let outcome = harness
        .enter(&config, ASK_CODE, &mut first)
        .expect("a step that failed after its wait returns the wait");

    assert_eq!(first.read_refused, Some(true), "the door refused the read");
    assert!(
        matches!(outcome.status, EngineExecutorStatus::Waiting(_)),
        "the run parks on its ask: {:?}",
        outcome.status
    );
    assert_eq!(outcome.steps_run, 1);
    let stored = vault
        .get_code_run_replay_record(&run_id)
        .expect("read replay")
        .expect("stored replay");
    assert_eq!(
        stored, outcome.replay_record,
        "the parked step is committed"
    );
    let observation = load_utf8_output(
        &ExecutorStorage::Canonical(vault.as_ref()),
        &stored,
        &observation_output_path(0),
    )
    .expect("the failed step's observation");
    assert!(
        observation.starts_with("Host bridge call failed: "),
        "the failure is the step's observation: {observation}"
    );

    let mut unready = SourceStep::new(Vec::new(), JsCodeModeStepOutcome::complete("must not run"));
    let reentered = harness
        .enter(&config, ASK_CODE, &mut unready)
        .expect("the parked run re-parks");
    assert_eq!(reentered.status, outcome.status);
    assert!(
        unready.seen.is_empty(),
        "a parked run runs nothing before its reply"
    );
}

#[test]
fn a_task_run_hashes_as_before() {
    let run_id = entity(0xC5);
    let task_config = executor_config(run_id, EngineExecutorLimits::default());
    assert_eq!(
        task_config.caller_source_digest, None,
        "no source means a task run"
    );
    let continuation = [0xA5; 32];
    for (session_ref, route_target, continuation) in [
        (None, None, None),
        (None, None, Some(&continuation)),
        (Some("sess-task-hash"), None, None),
        (Some("sess-task-hash"), Some(RouteTarget::Base), None),
        (Some("sess-task-hash"), Some(RouteTarget::Discard), None),
        (
            Some("sess-task-hash"),
            Some(RouteTarget::Overlay),
            Some(&continuation),
        ),
    ] {
        assert_eq!(
            executor_config_hash_for_binding(session_ref, route_target, &task_config, continuation),
            legacy_task_config_hash(session_ref, route_target, &task_config, continuation),
            "a task config hashes exactly as before"
        );
    }

    let source_a = source_config(run_id, WRITE_CODE);
    let source_b = source_config(run_id, OTHER_CODE);
    let task_hash = executor_config_hash_for_binding(None, None, &task_config, None);
    let hash_a = executor_config_hash_for_binding(None, None, &source_a, None);
    let hash_b = executor_config_hash_for_binding(None, None, &source_b, None);
    assert_ne!(
        hash_a, task_hash,
        "a source config hashes apart from a task run"
    );
    assert_ne!(hash_a, hash_b, "two codes hash apart under the same run");
    assert_eq!(
        hash_a,
        executor_config_hash_for_binding(None, None, &source_config(run_id, WRITE_CODE), None),
        "the same code hashes the same"
    );
    let unbound = EngineExecutorConfig {
        caller_source_digest: None,
        ..source_a.clone()
    };
    assert_ne!(
        hash_a,
        executor_config_hash_for_binding(None, None, &unbound, None),
        "the digest itself is bound, not only the config's other fields"
    );
}

#[test]
fn a_source_run_is_never_resumed_as_a_task() {
    let (_dir, vault) = open_test_vault();
    let vault = Arc::new(vault);
    let harness = SourceHarness::new(&vault);
    let run_id = entity(0xC6);
    let source = source_config(run_id, WRITE_CODE);

    let mut step = SourceStep::new(
        vec![create_task()],
        JsCodeModeStepOutcome::complete("written"),
    );
    harness
        .enter(&source, WRITE_CODE, &mut step)
        .expect("the source entry completes");
    let committed = vault
        .get_code_run_replay_record(&run_id)
        .expect("read replay")
        .expect("stored replay");
    let written = written_tasks_and_claims(&vault);

    // The same run through the task REPL: refused, and nothing runs. The
    // no-model backend stays bound, so a model turn would fail the test.
    let task = executor_config(run_id, EngineExecutorLimits::default());
    let backend = NoModelBackend;
    let lease = BudgetLease::for_test("task-resume-lease");
    let mut retry = SourceStep::new(
        vec![create_task()],
        JsCodeModeStepOutcome::complete("must not run"),
    );
    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut retry, &harness.gated_write);
    let err =
        block_on_ready(executor.run(&task)).expect_err("a source run never resumes as a task");

    assert!(matches!(
        err,
        EngineExecutorError::Engine(Error::InvalidConfig(_))
    ));
    assert!(
        err.to_string().contains("cannot resume as a task run"),
        "the task REPL refuses the source run's mode, not its config: {err}"
    );
    assert!(retry.seen.is_empty(), "the refused entry runs nothing");
    assert_eq!(
        vault
            .get_code_run_replay_record(&run_id)
            .expect("read replay")
            .expect("stored replay"),
        committed,
        "the record is unchanged by the refused entry"
    );
    assert_eq!(
        written_tasks_and_claims(&vault),
        written,
        "the vault is unchanged by the refused entry"
    );
}

/// The config hash's input sequence before the caller-source branch: the
/// task path, byte for byte (FIX EXECUTE-CALLER-CODE). A task config must
/// hash exactly this; anything else is a task-mode regression.
fn legacy_task_config_hash(
    session_ref: Option<&str>,
    route_target: Option<RouteTarget>,
    config: &EngineExecutorConfig,
    continuation: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut hasher = LegacyDigest::new(purposes::engine_executor::CONFIG);
    hash_bytes(
        &mut hasher,
        purposes::engine_executor::CONFIG.tag().as_bytes(),
    );
    match session_ref {
        None => hash_bytes(&mut hasher, b"storage:canonical"),
        Some(session_ref) => {
            hash_bytes(&mut hasher, b"storage:off-record-session");
            hash_str(&mut hasher, session_ref);
        }
    }
    if let Some(target) = route_target {
        hash_bytes(
            &mut hasher,
            match target {
                RouteTarget::Overlay => b"route:overlay",
                RouteTarget::Base => b"route:base",
                RouteTarget::Discard => b"discard",
            },
        );
    }
    hash_str(&mut hasher, &config.run_id.to_hex());
    hash_str(&mut hasher, &config.task);
    hash_str(&mut hasher, config.model.as_str());
    hash_str(
        &mut hasher,
        match config.model_locality {
            ModelLocality::OnDevice => "on_device",
            ModelLocality::OwnServer => "own_server",
            ModelLocality::ThirdParty => "third_party",
        },
    );
    if let Some(effort) = config.seat_effort {
        hash_str(&mut hasher, &format!("seat_effort:{effort:?}"));
    }
    hash_str(&mut hasher, config.global_tier.as_str());
    hash_u64(&mut hasher, config.determinism.frozen_unix_ms);
    hash_bytes(&mut hasher, &config.determinism.rng_seed);
    if let Some(digest) = continuation {
        hash_bytes(&mut hasher, b"continuation");
        hash_bytes(&mut hasher, digest);
    }
    hasher.finish()
}

/// A number: its 8 bytes, big-endian, with no length.
fn hash_u64(hasher: &mut LegacyDigest, value: u64) {
    hasher.raw(&value.to_be_bytes());
}

/// A field: a u64 big-endian length and its bytes.
fn hash_bytes(hasher: &mut LegacyDigest, bytes: &[u8]) {
    hasher.len_u64_be(bytes.len()).raw(bytes);
}

fn hash_str(hasher: &mut LegacyDigest, value: &str) {
    hash_bytes(hasher, value.as_bytes());
}
