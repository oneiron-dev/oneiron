use super::*;

fn entity_type_count(vault: &Vault, entity_type: u8) -> usize {
    vault
        .entities_by_type(entity_type)
        .expect("read typed entities")
        .len()
}

fn run_speech_step(
    vault: &Vault,
    gated_write: &GatedActorWrite<'_>,
    run_id: EntityId,
    calls: Vec<SelfCall>,
    observation: &str,
) {
    let backend = FixtureBackend::new(["self.speak('same words');"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime =
        FixtureRuntime::new([JsCodeModeStepOutcome::complete(observation)]).with_calls([calls]);
    let config = executor_config(run_id, EngineExecutorLimits::default());
    let mut executor =
        EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, gated_write);

    let outcome = block_on_ready(executor.run(&config)).expect("executor run");
    assert_eq!(outcome.status, EngineExecutorStatus::Complete);
}

/// Durable run identity is part of every canonical transcript identity. Two
/// replay records may deliberately share a host run ref without sharing their
/// conversation, turn, or bridge-position MESSAGE.
#[test]
fn distinct_executor_run_ids_do_not_share_explicit_speech_identity() {
    let (_dir, vault) = open_test_vault();
    let gated_write = gated_actor_write(&vault, "shared-run-ref");
    let before = [
        entity_type_count(&vault, crate::registry::ENTITY_TYPE_CONVERSATION),
        entity_type_count(&vault, crate::registry::ENTITY_TYPE_TURN),
        entity_type_count(&vault, crate::registry::ENTITY_TYPE_MESSAGE),
    ];

    for run_id in [entity(0xE0), entity(0xE2)] {
        run_speech_step(
            &vault,
            &gated_write,
            run_id,
            vec![SelfCall::Speak(SelfSpeechCall::new("same words"))],
            "same words",
        );
    }

    assert_eq!(
        [
            entity_type_count(&vault, crate::registry::ENTITY_TYPE_CONVERSATION),
            entity_type_count(&vault, crate::registry::ENTITY_TYPE_TURN),
            entity_type_count(&vault, crate::registry::ENTITY_TYPE_MESSAGE),
        ],
        [before[0] + 2, before[1] + 2, before[2] + 2],
        "independent durable runs get independent conversation/turn/message rows",
    );
}

/// The implicit trailing-speech path receives the same durable run identity as
/// an explicit bridge dispatch. Its deterministic IDs cannot collapse two
/// replay records that happen to share a dispatcher run ref.
#[test]
fn distinct_executor_run_ids_do_not_share_fallback_speech_identity() {
    let (_dir, vault) = open_test_vault();
    let gated_write = gated_actor_write(&vault, "shared-fallback-run-ref");
    let before = [
        entity_type_count(&vault, crate::registry::ENTITY_TYPE_CONVERSATION),
        entity_type_count(&vault, crate::registry::ENTITY_TYPE_TURN),
        entity_type_count(&vault, crate::registry::ENTITY_TYPE_MESSAGE),
    ];

    for run_id in [entity(0xE3), entity(0xE4)] {
        run_speech_step(&vault, &gated_write, run_id, Vec::new(), "same words");
    }

    assert_eq!(
        [
            entity_type_count(&vault, crate::registry::ENTITY_TYPE_CONVERSATION),
            entity_type_count(&vault, crate::registry::ENTITY_TYPE_TURN),
            entity_type_count(&vault, crate::registry::ENTITY_TYPE_MESSAGE),
        ],
        [before[0] + 2, before[1] + 2, before[2] + 2],
        "independent fallback emissions get independent transcript identities",
    );
}

/// The compatibility witness door has no durable run id, so it keeps the
/// legacy run-ref identity family while allocating a fresh bounded order for
/// each ordinary call. The explicit-order door still uses exactly the caller's
/// order and does not advance the compatibility allocator.
#[test]
fn public_witness_turn_calls_append_at_distinct_orders() {
    let (_dir, vault) = open_test_vault();
    let backend = FixtureBackend::new(std::iter::empty::<&str>());
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new(std::iter::empty::<JsCodeModeStepOutcome>());
    let gated_write = gated_actor_write(&vault, "standalone-witness-run");
    let executor = EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);

    executor
        .witness_turn(ExecutorUtterance::Speak, "automatic zero", 10)
        .expect("first automatic witness");
    executor
        .witness_turn_at(ExecutorUtterance::Express, "explicit seven", 11, 7)
        .expect("explicit-order witness");
    executor
        .witness_turn(ExecutorUtterance::Think, "automatic one", 12)
        .expect("second automatic witness");

    assert_eq!(
        executor_bubbles(&vault, entity(0xA0)),
        vec![
            (
                "executor.speak".to_owned(),
                "automatic zero".to_owned(),
                true,
                0
            ),
            (
                "executor.think".to_owned(),
                "automatic one".to_owned(),
                false,
                1
            ),
            (
                "executor.express".to_owned(),
                "explicit seven".to_owned(),
                true,
                7
            ),
        ],
    );

    let before = entity_type_count(&vault, crate::registry::ENTITY_TYPE_MESSAGE);
    executor
        .witness_turn_at(
            ExecutorUtterance::Speak,
            "outside the bounded order domain",
            13,
            crate::gate::MAX_WITNESS_MESSAGE_ORDER + 1,
        )
        .expect_err("an out-of-range explicit order is refused");
    assert_eq!(
        entity_type_count(&vault, crate::registry::ENTITY_TYPE_MESSAGE),
        before,
        "order refusal leaves the transcript unchanged",
    );
}

struct ReplayConflictAfterSpeechRuntime<'a> {
    vault: &'a Vault,
    competing_record: Option<CodeRunReplayRecord>,
    call: Option<SelfCall>,
}

impl JsCodeModeRuntime for ReplayConflictAfterSpeechRuntime<'_> {
    fn run_step(
        &mut self,
        _step: JsCodeModeStep<'_>,
        host: &mut dyn JsCodeModeHost,
    ) -> Result<JsCodeModeStepOutcome> {
        let call = self.call.take().ok_or(Error::InvariantViolation(
            "missing conflict fixture speech call",
        ))?;
        let _ = host.dispatch_self(call)?;
        let record = self
            .competing_record
            .take()
            .ok_or(Error::InvariantViolation("missing competing replay record"))?;
        self.vault.put_code_run_replay_record(&record)?;
        Ok(JsCodeModeStepOutcome::complete(""))
    }
}

fn initial_executor_replay_record(
    vault: &Vault,
    config: &EngineExecutorConfig,
) -> CodeRunReplayRecord {
    let mut record = CodeRunReplayRecord::new(config.run_id, config.determinism);
    super::super::record_config_marker(
        &crate::code_run::ExecutorStorage::Canonical(vault),
        &mut record,
        config,
    )
    .expect("record competing config marker");
    record
}

fn leave_speech_before_replay_cas(
    vault: &Vault,
    gated_write: &GatedActorWrite<'_>,
    config: &EngineExecutorConfig,
) {
    let backend = FixtureBackend::new(["self.speak('same words');"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = ReplayConflictAfterSpeechRuntime {
        vault,
        competing_record: Some(initial_executor_replay_record(vault, config)),
        call: Some(SelfCall::Speak(SelfSpeechCall::new("same words"))),
    };
    let mut executor =
        EngineNativeExecutor::new(vault, &backend, &lease, &mut runtime, gated_write);

    let error = block_on_ready(executor.run(config))
        .expect_err("competing initial replay record must lose the executor CAS");
    assert!(matches!(
        error,
        EngineExecutorError::Engine(Error::ConcurrentWrite(_))
    ));
}

#[derive(Debug, PartialEq, Eq)]
struct TranscriptSnapshot {
    rows: Vec<(u8, EntityId, Vec<u8>)>,
    message_edges: Vec<(EntityId, Vec<(EdgeKind, EntityId)>)>,
}

fn transcript_snapshot(vault: &Vault) -> TranscriptSnapshot {
    let mut rows = Vec::new();
    let mut message_edges = Vec::new();
    for entity_type in [
        crate::registry::ENTITY_TYPE_CONVERSATION,
        crate::registry::ENTITY_TYPE_TURN,
        crate::registry::ENTITY_TYPE_MESSAGE,
    ] {
        for id in vault
            .entities_by_type(entity_type)
            .expect("read transcript rows")
        {
            rows.push((
                entity_type,
                id,
                vault
                    .get_raw(&id)
                    .expect("read transcript row")
                    .expect("typed transcript row exists"),
            ));
            if entity_type == crate::registry::ENTITY_TYPE_MESSAGE {
                message_edges.push((
                    id,
                    vault
                        .edges_out(&id)
                        .expect("read message edges")
                        .into_iter()
                        .map(|edge| (edge.kind, edge.target))
                        .collect(),
                ));
            }
        }
    }
    TranscriptSnapshot {
        rows,
        message_edges,
    }
}

/// A speech witness can commit before the replay-record compare-and-set. When
/// that CAS loses, retrying the same canonical call must treat the existing
/// MESSAGE and its verified turn topology as an idempotent success.
#[test]
fn same_body_speech_retry_after_replay_cas_failure_is_idempotent() {
    let (_dir, vault) = open_test_vault();
    let gated_write = gated_actor_write(&vault, "crash-retry-run");
    let config = executor_config(entity(0xE5), EngineExecutorLimits::default());

    leave_speech_before_replay_cas(&vault, &gated_write, &config);
    let before_retry = transcript_snapshot(&vault);
    assert_eq!(
        before_retry
            .rows
            .iter()
            .filter(|(entity_type, _, _)| { *entity_type == crate::registry::ENTITY_TYPE_MESSAGE })
            .count(),
        1,
    );

    run_speech_step(
        &vault,
        &gated_write,
        config.run_id,
        vec![SelfCall::Speak(SelfSpeechCall::new("same words"))],
        "same words",
    );

    assert_eq!(
        transcript_snapshot(&vault),
        before_retry,
        "the exact retry neither rewrites nor reparents the existing transcript",
    );
    let replay = vault
        .get_code_run_replay_record(&config.run_id)
        .expect("read replay")
        .expect("retry persisted replay");
    assert_eq!(replay.bridge_calls.len(), 1);
    assert_eq!(replay.step_checkpoints.len(), 1);
}

/// The same crash window is not an overwrite grant. A retry that changes the
/// effect at the occupied bridge position is refused, and the winning MESSAGE,
/// TURN, conversation, authorship, and parent edges stay byte-for-byte intact.
#[test]
fn divergent_speech_retry_after_replay_cas_failure_is_fail_closed() {
    let (_dir, vault) = open_test_vault();
    let gated_write = gated_actor_write(&vault, "divergent-crash-retry-run");
    let config = executor_config(entity(0xE6), EngineExecutorLimits::default());

    leave_speech_before_replay_cas(&vault, &gated_write, &config);
    let winner = transcript_snapshot(&vault);

    let backend = FixtureBackend::new(["self.think('same words');"]);
    let lease = BudgetLease::for_test("executor-lease");
    let mut runtime = FixtureRuntime::new([JsCodeModeStepOutcome::complete("")])
        .with_calls([vec![SelfCall::Think(SelfSpeechCall::new("same words"))]]);
    let mut executor =
        EngineNativeExecutor::new(&vault, &backend, &lease, &mut runtime, &gated_write);
    block_on_ready(executor.run(&config))
        .expect_err("a different effect cannot take over the occupied MESSAGE id");

    assert_eq!(
        transcript_snapshot(&vault),
        winner,
        "divergent retry refusal has no transcript or topology mutation",
    );
}
