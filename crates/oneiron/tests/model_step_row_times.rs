//! A model step's rows are stamped in Unix seconds, as every claim and
//! entity row is (FIX COMPACTION-STEP-LEARNED-AT-MILLISECONDS and FIX
//! MODEL-STEP-ROW-TIMES-IN-MILLISECONDS). Each writer of the family is
//! handed its pass's clock in milliseconds: a compaction pass's wall clock,
//! a Dreamer step's and a trap's `now_ms`. The claim's own `at` keeps those
//! milliseconds, since step and trap waits compare it with that clock; the
//! occurred range and the learned time of each row the writer files hold the
//! same instant's second. On main every one of these rows held milliseconds.
//!
//! A trap signal sent from the TASK side, whose clock is the vault's Unix
//! second, reaches the trap as that second's milliseconds.
//!
//! The Dreamer step, the trap and the peer-result signal run on public
//! paths. The compaction step
//! files through its test door, so it is built with `--cfg
//! oneiron_test_support`: `RUSTFLAGS="--cfg oneiron_test_support" cargo test
//! --locked -p oneiron --all-features --test model_step_row_times`. On the
//! testkit: a copy of the empty fixture vault, and a scripted model that
//! answers each prompt by its digest.
use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::dreamer_runner::{
    DreamerRunnerStore, EnqueueDreamerAttempt, EnqueueDreamerAttemptOutcome,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm::{
    DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES, DREAMER_STEP_PREDICATE, DREAMER_TRAP_PREDICATE,
    DreamerTrapKind, DreamerTrapState, DurableStepContext, Scope, StepOutcome, call_as_step,
    open_trap, register_wait,
};
use oneiron::registry::{ENTITY_TYPE_BLOB_ARTIFACT, ENTITY_TYPE_CLAIM, ENTITY_TYPE_PERSON};
use oneiron::temporal::TimeRange;
use oneiron::write_envelope::WriteActor;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, CallClass, CallEnvelope, CallPurpose, ContentPart,
    LlmMessage, LlmMessageRole, LlmRequest, ModelId, ModelLocality, ModelTierRef, ResponseFormat,
    TierPrecedence,
};
use oneiron::{EntityId, Vault};
use oneiron_testkit::{FixtureVault, ScriptedBackend, Step, fixture_cache};

/// A pass clock in milliseconds that is not a whole second, so a row stamped
/// with it and a row stamped with its second differ.
const PASS_MS: u64 = 10_123;
/// The trap's second clock reading, for its `waiting` transition.
const WAIT_MS: u64 = 10_456;
/// The second both clock readings fall in.
const PASS_SECOND: u64 = 10;

fn block_on<F: Future>(future: F) -> F::Output {
    struct ThreadWaker(std::thread::Thread);
    impl std::task::Wake for ThreadWaker {
        fn wake(self: Arc<Self>) {
            self.0.unpark();
        }
    }
    let waker = Waker::from(Arc::new(ThreadWaker(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(output) => return output,
            Poll::Pending => std::thread::park(),
        }
    }
}

fn request(text: &str) -> LlmRequest {
    LlmRequest {
        model: ModelId::new("test/model@r1").expect("model id"),
        envelope: CallEnvelope {
            seat_effort: None,
            scope: Scope::default(),
            purpose: CallPurpose::Consolidation,
            class: CallClass::BestEffort,
            tier: TierPrecedence::for_purpose(
                &CallPurpose::Consolidation,
                ModelTierRef("default".into()),
            ),
            response_format: ResponseFormat::Text,
            locality: ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
        },
        messages: vec![LlmMessage {
            role: LlmMessageRole::User,
            content: vec![ContentPart::Text {
                text: text.to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: std::collections::BTreeMap::new(),
        provider_options: std::collections::BTreeMap::new(),
        host_segments: None,
    }
}

fn person(vault: &Vault) -> EntityId {
    let id = EntityId::now();
    vault
        .put_entity(
            &id,
            ENTITY_TYPE_PERSON,
            TimeRange { start: 10, end: 10 },
            10,
            b"human",
        )
        .expect("a person");
    id
}

fn enqueued_attempt(vault: &Vault, attempt_type: &str) -> oneiron::attempt_queue::AttemptId {
    match DreamerRunnerStore::new(vault)
        .enqueue(EnqueueDreamerAttempt {
            attempt_type: attempt_type.to_owned(),
            input: rmpv::Value::from("input"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-test".to_owned()),
            now: 10,
        })
        .expect("attempt")
    {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        other => panic!("unexpected enqueue outcome: {other:?}"),
    }
}

/// The ids of the vault's rows of `entity_type`.
fn rows_of(vault: &Vault, entity_type: u8) -> BTreeSet<EntityId> {
    vault
        .entities_by_type(entity_type)
        .expect("rows by type")
        .into_iter()
        .collect()
}

/// The vault's claims of `predicate`, by id.
fn claims_of(vault: &Vault, predicate: &str) -> BTreeSet<EntityId> {
    rows_of(vault, ENTITY_TYPE_CLAIM)
        .into_iter()
        .filter(|id| {
            vault
                .get_claim(id)
                .expect("claim")
                .is_some_and(|body| body.predicate == predicate)
        })
        .collect()
}

/// The one id `after` holds that `before` does not.
fn the_new_one(before: &BTreeSet<EntityId>, after: &BTreeSet<EntityId>, what: &str) -> EntityId {
    let new: Vec<EntityId> = after.difference(before).copied().collect();
    let [id] = new.as_slice() else {
        panic!("one new {what}, found {}", new.len());
    };
    *id
}

/// The `at` a step or trap claim's value carries.
fn claim_value_at(vault: &Vault, claim: &EntityId) -> u64 {
    let body = vault.get_claim(claim).expect("claim").expect("the claim");
    let rmpv::Value::Map(entries) = &body.value else {
        panic!("a step or trap claim's value is a map");
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some("at"))
        .and_then(|(_, value)| value.as_u64())
        .expect("the claim's value carries `at`")
}

/// `row`'s occurred range and learned time are the one second `second`.
fn assert_stamped_at(vault: &Vault, row: &EntityId, second: u64, what: &str) {
    assert_eq!(
        vault.get_learned_at(row).expect("learned time"),
        second,
        "{what} is learned at the pass's Unix second, not its milliseconds"
    );
    assert_eq!(
        vault.get_occurred(row).expect("occurred range"),
        TimeRange {
            start: second,
            end: second,
        },
        "{what} occurred at the pass's Unix second, not its milliseconds"
    );
}

#[test]
fn a_dreamer_steps_claim_and_response_artifact_are_stamped_in_unix_seconds() {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open().expect("vault");
    let actor = person(&vault);
    let subject = person(&vault);
    let ctx = DurableStepContext {
        vault: &vault,
        attempt_id: enqueued_attempt(&vault, "step-row-times-test"),
        run_id: Some("run-test".to_owned()),
        envelope_actor: WriteActor::new(actor, EdgeActorClass::Agent),
        subject,
        deadline: None,
        now_ms: PASS_MS,
        spend_scope: None,
        wake_pass_bound: false,
    };
    let guard =
        BudgetGuard::with_reserve_units("step-test", 10_000, 500, BudgetExhaustionPolicy::Suspend);
    let step_request = request("a consolidation prompt");
    // Above the inline bound, so the answer lives in a response artifact.
    let answer = "a long consolidated answer. ".repeat(DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES / 16);
    assert!(
        answer.len() > DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES,
        "FIXTURE: the answer is above the inline bound"
    );
    let backend = ScriptedBackend::new(vec![
        Step::text(
            "long",
            ScriptedBackend::digest_of(&step_request),
            answer.as_str(),
        )
        .buffered()
        .usage(100, 50),
    ])
    .expect("the script");
    let claims_before = claims_of(&vault, DREAMER_STEP_PREDICATE);
    let artifacts_before = rows_of(&vault, ENTITY_TYPE_BLOB_ARTIFACT);
    assert!(
        matches!(
            block_on(call_as_step(&ctx, &backend, &guard, step_request)).expect("the step"),
            StepOutcome::Finished { .. }
        ),
        "FIXTURE: the step finishes"
    );
    assert_eq!(backend.finish().len(), 1, "FIXTURE: the step made one call");
    let claim = the_new_one(
        &claims_before,
        &claims_of(&vault, DREAMER_STEP_PREDICATE),
        "step claim",
    );
    let artifact = the_new_one(
        &artifacts_before,
        &rows_of(&vault, ENTITY_TYPE_BLOB_ARTIFACT),
        "response artifact",
    );
    assert_stamped_at(&vault, &claim, PASS_SECOND, "the step claim");
    assert_stamped_at(
        &vault,
        &artifact,
        PASS_SECOND,
        "the step's response artifact",
    );
    assert_eq!(
        claim_value_at(&vault, &claim),
        PASS_MS,
        "the step claim's own `at` keeps the pass clock's milliseconds"
    );
}

#[test]
fn a_traps_anchor_and_transition_are_stamped_in_unix_seconds() {
    let copy = FixtureVault::empty(&fixture_cache!())
        .expect("the empty fixture")
        .copy()
        .expect("a private copy");
    let vault = copy.open().expect("vault");
    let actor = person(&vault);
    let subject = person(&vault);
    let ctx = DurableStepContext {
        vault: &vault,
        attempt_id: enqueued_attempt(&vault, "trap-row-times-test"),
        run_id: Some("run-test".to_owned()),
        envelope_actor: WriteActor::new(actor, EdgeActorClass::Agent),
        subject,
        deadline: None,
        now_ms: PASS_MS,
        spend_scope: None,
        wake_pass_bound: false,
    };
    let trap = open_trap(&vault, &ctx, DreamerTrapKind::Consent, [7; 32], "a wait")
        .expect("the trap opens");
    let anchor = trap.trap_claim_id;
    assert_stamped_at(&vault, &anchor, PASS_SECOND, "the trap's anchor");
    assert_eq!(
        claim_value_at(&vault, &anchor),
        PASS_MS,
        "the anchor's own `at` keeps the pass clock's milliseconds"
    );

    let before = claims_of(&vault, DREAMER_TRAP_PREDICATE);
    assert!(
        matches!(
            register_wait(&vault, &trap, WAIT_MS).expect("the trap waits"),
            DreamerTrapState::Waiting
        ),
        "FIXTURE: the trap moves from created to waiting"
    );
    let transition = the_new_one(
        &before,
        &claims_of(&vault, DREAMER_TRAP_PREDICATE),
        "trap transition",
    );
    assert_stamped_at(
        &vault,
        &transition,
        PASS_SECOND,
        "the trap's waiting transition",
    );
    assert_eq!(
        claim_value_at(&vault, &transition),
        WAIT_MS,
        "the transition's own `at` keeps the clock's milliseconds"
    );
    assert_eq!(
        vault.get_occurred(&anchor).expect("occurred range"),
        TimeRange {
            start: PASS_SECOND,
            end: PASS_SECOND,
        },
        "the superseded anchor closes at the transition's Unix second"
    );
}

/// A peer-result wait opened and registered on the trap's millisecond clock
/// is signalled by the TASK side, whose clock is the vault's Unix second
/// (blind review round 1 of #10378). The settling second reaches the trap as
/// milliseconds, so the `sent` transition is stamped at that second and its
/// `at` is that second's milliseconds, and the waiting head closes there. On
/// main the second lost to the head's milliseconds (`now.max(head.at)`): the
/// transition took the wait's start, stamped in milliseconds; with the row
/// times in seconds alone it would sit 120 seconds before the answer.
#[test]
fn a_peer_results_sent_transition_is_stamped_at_the_tasks_settling_second() {
    use oneiron::config::VaultConfig;
    use oneiron::dreamer_runner::{DreamerParkCause, ParkDreamerAttempt};
    use oneiron::llm::{register_peer_result_wait, trap_for_durable_wait, trap_park_owner};
    use oneiron::task_verb::{
        TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition,
    };

    /// The trap's clock when the wait opens and registers, in milliseconds.
    const WAIT_OPEN_MS: u64 = 1_790_000_000_000;
    /// The Unix second the wait opens in.
    const WAIT_OPEN_SECOND: u64 = 1_790_000_000;
    /// The Unix second the peer's result settles the TASK, 120 seconds later.
    const SETTLED_SECOND: u64 = 1_790_000_120;
    // The first-party connector actor: the one identity the default policy
    // manifest grants an Auto ceiling, so the delegating create effects (as
    // `cb_oracle_tasks` arms its BYOA wait).
    const ASKER_BYTES: [u8; 16] = [0xE1; 16];
    let step_hash = [0x6Du8; 32];

    let directory = tempfile::tempdir().expect("a directory");
    let vault = Vault::open(directory.path(), VaultConfig::device()).expect("vault");
    let put_person = |id: EntityId, body: &[u8]| {
        vault
            .put_entity(
                &id,
                ENTITY_TYPE_PERSON,
                TimeRange { start: 1, end: 1 },
                1,
                body,
            )
            .expect("a person");
    };
    let asker = EntityId::from_bytes(ASKER_BYTES).expect("asker id");
    let peer = EntityId::from_bytes([0x6E; 16]).expect("peer id");
    put_person(asker, b"asker");
    put_person(peer, b"peer");

    let (receipt, wait) = vault
        .memory(asker, EdgeActorClass::Agent)
        .delegate_task_and_wait(
            &TaskCreateSpec::new(
                rmpv::Value::from("delegated"),
                None,
                None,
                Some(WAIT_OPEN_SECOND),
            )
            .with_assignee(TaskAssignee::Peer { actor_ref: peer }),
        )
        .expect("FIXTURE: the delegation effects");
    let task_ref = receipt.task_ref.expect("the delegation mints one TASK");
    let runner = DreamerRunnerStore::new(&vault);
    let attempt_id = match runner
        .enqueue(EnqueueDreamerAttempt {
            attempt_type: "peer-result-row-times-test".to_owned(),
            input: rmpv::Value::from("step"),
            parent_attempt: None,
            dedupe_key: None,
            run_id: Some("run-test".to_owned()),
            now: WAIT_OPEN_SECOND,
        })
        .expect("attempt")
    {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
        other => panic!("unexpected enqueue outcome: {other:?}"),
    };
    let ctx = DurableStepContext {
        vault: &vault,
        attempt_id,
        run_id: Some("run-test".to_owned()),
        envelope_actor: WriteActor::new(asker, EdgeActorClass::Agent),
        subject: peer,
        deadline: None,
        now_ms: WAIT_OPEN_MS,
        spend_scope: None,
        wake_pass_bound: false,
    };
    let trap = open_trap(
        &vault,
        &ctx,
        trap_for_durable_wait(&wait, step_hash),
        step_hash,
        "peer result",
    )
    .expect("FIXTURE: the delegation trap opens");
    runner
        .park_attempt(ParkDreamerAttempt {
            attempt_id,
            reason: "peer result".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: trap_park_owner(&trap.trap_claim_id),
            carried_spend: None,
            now: WAIT_OPEN_SECOND,
        })
        .expect("FIXTURE: the step parks");
    let before_wait = claims_of(&vault, DREAMER_TRAP_PREDICATE);
    assert!(
        matches!(
            register_peer_result_wait(&vault, &trap, task_ref, WAIT_OPEN_MS)
                .expect("the wait registers"),
            DreamerTrapState::Waiting
        ),
        "FIXTURE: the unsettled TASK leaves the trap waiting"
    );
    let waiting = the_new_one(
        &before_wait,
        &claims_of(&vault, DREAMER_TRAP_PREDICATE),
        "waiting transition",
    );

    let result_ref = EntityId::from_bytes([0x6F; 16]).expect("result id");
    put_person(result_ref, b"the result");
    let before_signal = claims_of(&vault, DREAMER_TRAP_PREDICATE);
    vault
        .memory(peer, EdgeActorClass::Agent)
        .land_task_result(
            task_ref,
            &TaskResultInput {
                result_ref,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: SETTLED_SECOND,
            },
        )
        .expect("the peer lands its result");
    let sent = the_new_one(
        &before_signal,
        &claims_of(&vault, DREAMER_TRAP_PREDICATE),
        "sent transition",
    );
    assert_stamped_at(
        &vault,
        &sent,
        SETTLED_SECOND,
        "the sent transition of the settling TASK",
    );
    assert_eq!(
        claim_value_at(&vault, &sent),
        SETTLED_SECOND * 1_000,
        "the sent transition's own `at` is the settling second in milliseconds"
    );
    assert_eq!(
        vault.get_occurred(&waiting).expect("occurred range"),
        TimeRange {
            start: WAIT_OPEN_SECOND,
            end: SETTLED_SECOND,
        },
        "the waiting head closes at the settling second"
    );
}

#[cfg(oneiron_test_support)]
#[test]
fn a_compaction_steps_claim_and_response_rows_are_stamped_in_unix_seconds() {
    use oneiron::registry::ENTITY_TYPE_ASSET;
    use oneiron::test_doors::compaction_step_read::file_compaction_step;

    let directory = tempfile::tempdir().expect("a directory");
    let vault =
        Vault::open_owned(directory.path(), oneiron::VaultConfig::default()).expect("vault");
    let owner = vault.ensure_embedded_owner_actor().expect("the owner");
    let proof = vault
        .memory(owner, EdgeActorClass::Human)
        .embedded_owner("vault.agents.create")
        .expect("the owner's proof");
    let scribe = EntityId::now();
    let definition: oneiron::verbs::AgentDefinitionSpec =
        serde_json::from_value(serde_json::json!({
            "agent_id": "scribe",
            "display_name": "scribe",
            "desc": "scribe",
            "version": "1",
            "ceiling": "auto",
        }))
        .expect("the definition");
    oneiron::verbs::create_agent_definition_as(
        &vault,
        &proof,
        oneiron::verbs::AgentDefinitionCreateRequest {
            agent_def_ref: scribe,
            definition,
        },
    )
    .expect("FIXTURE: the compactor's definition");
    let source = person(&vault);
    // Above the inline bound, so the answer lives in a response artifact
    // whose bytes a content ASSET holds.
    let answer = "the rest of the window. ".repeat(DREAMER_STEP_INLINE_RESPONSE_MAX_BYTES / 16);
    let artifacts_before = rows_of(&vault, ENTITY_TYPE_BLOB_ARTIFACT);
    let assets_before = rows_of(&vault, ENTITY_TYPE_ASSET);
    // The door files at the vault clock's wall milliseconds, as a pass does.
    let before_ms = vault.now_recorded_ms();
    let claim = file_compaction_step(
        &vault,
        "chat-compaction",
        EntityId::now(),
        scribe,
        vec![source],
        &answer,
    )
    .expect("the step files");
    let after_ms = vault.now_recorded_ms();
    let artifact = the_new_one(
        &artifacts_before,
        &rows_of(&vault, ENTITY_TYPE_BLOB_ARTIFACT),
        "response artifact",
    );
    let asset = the_new_one(
        &assets_before,
        &rows_of(&vault, ENTITY_TYPE_ASSET),
        "content ASSET",
    );
    let seconds = (before_ms / 1_000)..=(after_ms / 1_000);
    for (row, what) in [
        (claim, "the compaction step claim"),
        (artifact, "its response artifact"),
        (asset, "its response's content ASSET"),
    ] {
        let learned_at = vault.get_learned_at(&row).expect("learned time");
        assert!(
            seconds.contains(&learned_at),
            "{what} is learned at the pass's Unix second {seconds:?}, not {learned_at}"
        );
        let occurred = vault.get_occurred(&row).expect("occurred range");
        assert!(
            seconds.contains(&occurred.start) && seconds.contains(&occurred.end),
            "{what} occurred in the pass's Unix second {seconds:?}, not {occurred:?}"
        );
    }
    assert!(
        (before_ms..=after_ms).contains(&claim_value_at(&vault, &claim)),
        "the step claim's own `at` keeps the pass clock's milliseconds"
    );
}
