//! 6.5d-1 (budget typed wait): a step refused by its spend scope's hard cap parks typed on that
//! scope, and only that scope's room-leaving top-up wakes it.
//!
//! Tries A and B run under `guard_for_scope` guards of two hard root scopes whose caps sit well
//! below the guards' reserve; try C runs scopeless under a zero-limit guard. Each step goes through
//! the public `call_as_step` with a paid request and a backend that must not be called. Trap head
//! states read through `oneiron::test_doors::park_typed_wait`, built only under
//! `--cfg oneiron_test_support`.
//!
//! 6.5d-2 (answer typed waits): consent, peer and human parks each name their own code-run wait
//! key, admit only a trap consume, ignore an unrelated budget top-up, and wake only on their own
//! delivery: a consent reply, a peer TASK's terminal result, or a human answer.
//!
//! 6.5d-3 (seat typed waits): two tries parked on seat A and one on seat B name their seat, its
//! refusal generation and its reset; only their own seat's available write or the owner's release
//! resumes them, time alone wakes nothing, and a later refusal parks again at a new generation.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId, SpendState};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::code_run::{WaitDeliveries, WaitKey, park_and_bind_wait_trap};
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DREAMER_SERVER_PARK_OWNER, DreamerAttemptStatus,
    DreamerConsolidationScope, DreamerParkWait, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt, ModelSeatAvailability, ModelSeatAvailableSource,
    ModelSeatId, ParkResumer,
};
use oneiron::dreamer_runner::{
    DreamerParkWaitClass, DreamerParkedWait, ParkDreamerAttempt, ParkOwnerClass, ParkResume,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::memory::DreamerParkCauseView;
use oneiron::registry::ENTITY_TYPE_PERSON;
use oneiron::task_verb::{TaskAssignee, TaskCreateSpec, TaskResultInput, TaskTerminalDisposition};
use oneiron::test_doors::park_typed_wait as doors;
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor, DreamerParkCause,
    DreamerWakeDriver, RunWakePass, Vault, VaultConfig, WakeAttemptContext, WakeCancellation,
    WakePassDeadline, WakePassStop, WakeTrigger, WriteActor,
};
use oneiron::{EntityId, TimeRange};

/// The lease owner the fixture's tries claim under.
const LEASE_OWNER: &str = "park-typed-wait";
/// Root caps, each well below any guard reserve (the default reserve is thousands of units).
const CAP_A: u64 = 100;
const CAP_B: u64 = 200;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // A budget-exhausted step answers without parking the thread, so polling again immediately is
    // correct; the bound catches a future pending on anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("typed-wait step future pending on something other than an attempt-boundary yield");
}

/// A temporary vault opened with `config` and a process-memory device keystore, as the crate's test
/// opener opens one.
fn open_vault_with(config: VaultConfig) -> oneiron::Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), config)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Ok((dir, vault))
}

fn open_vault() -> oneiron::Result<(tempfile::TempDir, Vault)> {
    open_vault_with(VaultConfig::device())
}

/// The vault's embedded owner, authenticated: what an owner door takes.
fn embedded_owner_proof(vault: &Vault) -> oneiron::consent::AuthenticatedOwner {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    vault
        .authenticate_owner(
            owner,
            &owner.to_hex(),
            true,
            oneiron::store::GateDecisionId::now(),
        )
        .expect("owner proof")
}

/// One paid model request: a text step of the consolidation purpose on the owner's own server, so
/// the guard admits it on its paid line and a spent line refuses it.
fn paid_step_request(text: &str) -> llm::LlmRequest {
    llm::LlmRequest {
        model: llm::ModelId::new("test/model@r1").expect("model id"),
        envelope: llm::CallEnvelope {
            scope: llm::Scope::default(),
            purpose: llm::CallPurpose::Consolidation,
            class: llm::CallClass::BestEffort,
            tier: llm::TierPrecedence::for_purpose(
                &llm::CallPurpose::Consolidation,
                llm::ModelTierRef("default".into()),
            ),
            response_format: llm::ResponseFormat::Text,
            locality: llm::ModelLocality::OwnServer,
            host_keyless: false,
            host_paid: false,
            seat_effort: None,
        },
        messages: vec![llm::LlmMessage {
            role: llm::LlmMessageRole::User,
            content: vec![llm::ContentPart::Text {
                text: text.to_owned(),
                signature: None,
            }],
        }],
        tools: Vec::new(),
        params: Default::default(),
        provider_options: Default::default(),
        host_segments: None,
    }
}

/// A backend a spent budget must never reach: any call panics, and the count stays readable.
struct NeverBackend {
    calls: AtomicUsize,
}

impl NeverBackend {
    fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl llm::LlmBackend for NeverBackend {
    fn generate<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmGenerateFuture<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("a budget-exhausted step must not call its backend");
    }

    fn stream<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmStreamResult<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("a budget-exhausted step must not call its backend");
    }
}

/// One leased try: a micro consolidation attempt enqueued under `tag` and claimed under the
/// fixture's lease owner, so the step parks under a live lease.
fn leased_try(vault: &Vault, tag: &str, now: u64) -> oneiron::Result<AttemptRecord> {
    let store = DreamerRunnerStore::new(vault);
    let status = match store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: rmpv::Value::from(format!("input:{tag}")),
        parent_attempt: None,
        dedupe_key: Some(tag.to_owned()),
        run_id: None,
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => status,
        // The outcome enum is `#[non_exhaustive]` outside the crate.
        other => panic!("unexpected enqueue outcome {other:?}"),
    };
    let queue = AttemptQueue::new(vault);
    let ClaimOutcome::Claimed(row) = queue.claim_kind(
        DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: LEASE_OWNER.to_owned(),
            now: u64::MAX,
        },
    )?
    else {
        panic!("the enqueued try is ready to claim");
    };
    assert_eq!(
        row.id, status.attempt.id,
        "the claim takes the try just enqueued"
    );
    Ok(row)
}

/// 6.5d-1: the two scoped tries park typed on their own scopes with their queue generation, the
/// scopeless try parks untyped, a short top-up wakes nothing, and a room-leaving top-up of A wakes
/// only A, as the same queued try with its trap consumed.
#[test]
fn a_budget_typed_wait_wakes_only_on_its_own_scopes_room() -> Result<(), Box<dyn std::error::Error>>
{
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = embedded_owner_proof(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let store = DreamerRunnerStore::new(&vault);

    // Two open hard root scopes with caps well below any guard reserve.
    let scope_a = SpendScopeId::launch("owen-a")?;
    let scope_b = SpendScopeId::launch("yuki-b")?;
    let opened_a = dispatcher
        .open_root_spend_scope(
            scope_a.clone(),
            DeclaredMaximum {
                units: CAP_A,
                unit: LeaseUnit::tokens(),
            },
            Some(MaximumShown { at_ms: 10_000 }),
            10,
        )
        .expect("root scope A opens");
    assert!(opened_a.hard, "scope A is a hard cap");
    assert_eq!(opened_a.state, SpendState::Open, "scope A opens open");
    assert_eq!(opened_a.cap_units, CAP_A, "scope A opens under its cap");
    let opened_b = dispatcher
        .open_root_spend_scope(
            scope_b.clone(),
            DeclaredMaximum {
                units: CAP_B,
                unit: LeaseUnit::tokens(),
            },
            Some(MaximumShown { at_ms: 11_000 }),
            11,
        )
        .expect("root scope B opens");
    assert!(opened_b.hard, "scope B is a hard cap");
    assert_eq!(opened_b.state, SpendState::Open, "scope B opens open");
    assert_eq!(opened_b.cap_units, CAP_B, "scope B opens under its cap");

    // Each scoped step runs under its scope's guard; the scopeless step runs under a zero-limit
    // guard. Every cap sits below its guard's reserve, so every admission refuses exhausted.
    let guard_a = dispatcher.guard_for_scope(&scope_a)?;
    let guard_b = dispatcher.guard_for_scope(&scope_b)?;
    let asked_a = guard_a.reserve_units();
    let asked_b = guard_b.reserve_units();
    assert!(
        CAP_A < asked_a,
        "scope A's cap sits below the guard's reserve"
    );
    assert!(
        CAP_B < asked_b,
        "scope B's cap sits below the guard's reserve"
    );
    let guard_c = llm::BudgetGuard::with_reserve_units(
        "park-typed-wait-c",
        0,
        500,
        llm::BudgetExhaustionPolicy::Suspend,
    );

    let row_a = leased_try(&vault, "park-typed-wait-a", 20)?;
    let row_b = leased_try(&vault, "park-typed-wait-b", 21)?;
    let row_c = leased_try(&vault, "park-typed-wait-c", 22)?;
    assert_eq!(
        row_a.state.as_str(),
        "leased",
        "try A holds its lease before its step"
    );
    assert_eq!(
        row_b.state.as_str(),
        "leased",
        "try B holds its lease before its step"
    );
    assert_eq!(
        row_c.state.as_str(),
        "leased",
        "try C holds its lease before its step"
    );

    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let ctx_a = llm::DurableStepContext {
        vault: &vault,
        attempt_id: row_a.id,
        run_id: None,
        envelope_actor: actor,
        subject: owner,
        deadline: None,
        now_ms: 40_000,
        spend_scope: Some(scope_a.clone()),
    };
    let ctx_b = llm::DurableStepContext {
        vault: &vault,
        attempt_id: row_b.id,
        run_id: None,
        envelope_actor: actor,
        subject: owner,
        deadline: None,
        now_ms: 41_000,
        spend_scope: Some(scope_b.clone()),
    };
    let ctx_c = llm::DurableStepContext {
        vault: &vault,
        attempt_id: row_c.id,
        run_id: None,
        envelope_actor: actor,
        subject: owner,
        deadline: None,
        now_ms: 42_000,
        spend_scope: None,
    };

    let backend = NeverBackend::new();
    let outcome_a = block_on_ready(llm::call_as_step(
        &ctx_a,
        &backend,
        &guard_a,
        paid_step_request("park typed wait a"),
    ))
    .expect("try A's step answers");
    let llm::StepOutcome::Trapped { trap: trap_a, .. } = outcome_a else {
        panic!("try A's spent budget traps its step");
    };
    assert_eq!(
        trap_a.kind,
        llm::DreamerTrapKind::Budget,
        "try A's trap is a budget trap"
    );
    assert_eq!(
        backend.calls(),
        0,
        "try A's spent budget never calls its backend"
    );
    let outcome_b = block_on_ready(llm::call_as_step(
        &ctx_b,
        &backend,
        &guard_b,
        paid_step_request("park typed wait b"),
    ))
    .expect("try B's step answers");
    let llm::StepOutcome::Trapped { trap: trap_b, .. } = outcome_b else {
        panic!("try B's spent budget traps its step");
    };
    assert_eq!(
        trap_b.kind,
        llm::DreamerTrapKind::Budget,
        "try B's trap is a budget trap"
    );
    assert_eq!(
        backend.calls(),
        0,
        "try B's spent budget never calls its backend"
    );
    let outcome_c = block_on_ready(llm::call_as_step(
        &ctx_c,
        &backend,
        &guard_c,
        paid_step_request("park typed wait c"),
    ))
    .expect("try C's step answers");
    let llm::StepOutcome::Trapped { trap: trap_c, .. } = outcome_c else {
        panic!("try C's spent budget traps its step");
    };
    assert_eq!(
        trap_c.kind,
        llm::DreamerTrapKind::Budget,
        "try C's trap is a budget trap"
    );
    assert_eq!(
        backend.calls(),
        0,
        "try C's spent budget never calls its backend"
    );

    // Each runner registers its wait, so each trap waits for its signal.
    assert_eq!(
        llm::register_wait(&vault, &trap_a, 50_000)?,
        llm::DreamerTrapState::Waiting,
        "try A's trap waits for its signal"
    );
    assert_eq!(
        llm::register_wait(&vault, &trap_b, 51_000)?,
        llm::DreamerTrapState::Waiting,
        "try B's trap waits for its signal"
    );
    assert_eq!(
        llm::register_wait(&vault, &trap_c, 52_000)?,
        llm::DreamerTrapState::Waiting,
        "try C's trap waits for its signal"
    );

    // Each scoped try parks typed on its own scope with its queue generation; the scopeless try
    // parks untyped.
    let park_a = store.parked_attempt(row_a.id)?.expect("try A's park");
    assert_eq!(
        park_a.cause,
        DreamerParkCause::Signal,
        "try A's park waits on a signal"
    );
    assert_eq!(
        park_a.park_owner,
        llm::trap_park_owner(&trap_a.trap_claim_id),
        "try A's park sits under its trap's owner"
    );
    let Some(wait_a) = park_a.wait.as_ref() else {
        panic!("try A's park carries its scope's typed wait");
    };
    match &wait_a.wait {
        DreamerParkWait::Budget { scope, asked_units } => {
            assert_eq!(scope, &scope_a, "try A's wait names its own scope");
            assert_eq!(
                *asked_units, asked_a,
                "try A's wait asks the guard's reserve"
            );
        }
        _ => panic!("try A's park carries its scope's typed wait"),
    }
    let count_a = store
        .status(row_a.id)?
        .expect("try A's row")
        .attempt
        .attempt_count;
    assert_eq!(
        count_a, row_a.attempt_count,
        "parking keeps try A's lease generation"
    );
    assert_eq!(
        wait_a.lease_generation, count_a,
        "try A's wait stamps its queue generation"
    );
    let park_b = store.parked_attempt(row_b.id)?.expect("try B's park");
    assert_eq!(
        park_b.cause,
        DreamerParkCause::Signal,
        "try B's park waits on a signal"
    );
    assert_eq!(
        park_b.park_owner,
        llm::trap_park_owner(&trap_b.trap_claim_id),
        "try B's park sits under its trap's owner"
    );
    let Some(wait_b) = park_b.wait.as_ref() else {
        panic!("try B's park carries its scope's typed wait");
    };
    match &wait_b.wait {
        DreamerParkWait::Budget { scope, asked_units } => {
            assert_eq!(scope, &scope_b, "try B's wait names its own scope");
            assert_eq!(
                *asked_units, asked_b,
                "try B's wait asks the guard's reserve"
            );
        }
        _ => panic!("try B's park carries its scope's typed wait"),
    }
    let count_b = store
        .status(row_b.id)?
        .expect("try B's row")
        .attempt
        .attempt_count;
    assert_eq!(
        count_b, row_b.attempt_count,
        "parking keeps try B's lease generation"
    );
    assert_eq!(
        wait_b.lease_generation, count_b,
        "try B's wait stamps its queue generation"
    );
    let park_c = store.parked_attempt(row_c.id)?.expect("try C's park");
    assert_eq!(
        park_c.cause,
        DreamerParkCause::Signal,
        "try C's park waits on a signal"
    );
    assert_eq!(
        park_c.park_owner,
        llm::trap_park_owner(&trap_c.trap_claim_id),
        "try C's park sits under its trap's owner"
    );
    assert!(
        park_c.wait.is_none(),
        "the scopeless try parks without a typed wait"
    );

    // Only a top-up resumes a budget wait, and only the wait's own scope; the blind resumers stay
    // out.
    assert!(
        park_a.resumable_by(ParkResumer::BudgetTopUp),
        "a top-up may resume try A's budget wait"
    );
    assert!(
        park_b.resumable_by(ParkResumer::BudgetTopUp),
        "a top-up may resume try B's budget wait"
    );
    assert!(
        !park_c.resumable_by(ParkResumer::BudgetTopUp),
        "no top-up resumes the untyped park"
    );
    assert!(
        !park_a.resumable_by(ParkResumer::LaterPass),
        "no later pass resumes a budget wait"
    );
    assert!(
        !park_a.resumable_by(ParkResumer::BootRecovery),
        "no boot recovery resumes a budget wait"
    );
    assert!(
        !park_a.resumable_by(ParkResumer::OutageSweep),
        "no outage sweep resumes a budget wait"
    );

    assert_eq!(
        doors::trap_state(&vault, &trap_a)?,
        llm::DreamerTrapState::Waiting,
        "try A's trap waits before any top-up"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_b)?,
        llm::DreamerTrapState::Waiting,
        "try B's trap waits before any top-up"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_c)?,
        llm::DreamerTrapState::Waiting,
        "try C's trap waits before any top-up"
    );

    // A top-up of A that leaves less than the refused reserve wakes nothing.
    let short_cap = asked_a - 1;
    assert!(
        CAP_A < short_cap,
        "the short top-up still raises scope A's cap"
    );
    assert!(
        short_cap < asked_a,
        "the short top-up leaves less than the refused reserve"
    );
    let raised = dispatcher.top_up_spend_scope_as_owner(
        &proof,
        &scope_a,
        CAP_A,
        DeclaredMaximum {
            units: short_cap,
            unit: LeaseUnit::tokens(),
        },
        MaximumShown { at_ms: 60_000 },
    )?;
    assert_eq!(raised.cap_units, short_cap, "scope A's short top-up lands");
    assert!(
        store.parked_attempt(row_a.id)?.is_some(),
        "a short top-up resumes nothing on its own scope"
    );
    assert!(
        store.parked_attempt(row_b.id)?.is_some(),
        "a top-up of A leaves try B's park"
    );
    assert!(
        store.parked_attempt(row_c.id)?.is_some(),
        "a top-up of A leaves the untyped park"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_a)?,
        llm::DreamerTrapState::Waiting,
        "a short top-up leaves try A's trap waiting"
    );

    // A top-up of A that leaves room wakes only A, as the same queued try with its trap consumed.
    let room_cap = asked_a + 1_000;
    let raised = dispatcher.top_up_spend_scope_as_owner(
        &proof,
        &scope_a,
        short_cap,
        DeclaredMaximum {
            units: room_cap,
            unit: LeaseUnit::tokens(),
        },
        MaximumShown { at_ms: 70_000 },
    )?;
    assert_eq!(
        raised.cap_units, room_cap,
        "scope A's room-leaving top-up lands"
    );
    assert!(
        store.parked_attempt(row_a.id)?.is_none(),
        "the top-up wakes the try that waits on its scope"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_a)?,
        llm::DreamerTrapState::Consumed,
        "the woken try's trap is consumed"
    );
    let status_a = store.status(row_a.id)?.expect("try A's row after the wake");
    assert_eq!(status_a.attempt.id, row_a.id, "the woken try keeps its id");
    assert_eq!(
        status_a.attempt.state.as_str(),
        "queued",
        "the woken try queues again"
    );
    assert_eq!(
        status_a.attempt.attempt_count, row_a.attempt_count,
        "the woken try keeps its lease generation"
    );
    assert!(
        store.parked_attempt(row_b.id)?.is_some(),
        "a top-up of A leaves try B's park standing"
    );
    assert!(
        store.parked_attempt(row_c.id)?.is_some(),
        "a top-up of A leaves the untyped park standing"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_b)?,
        llm::DreamerTrapState::Waiting,
        "try B's trap still waits"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_c)?,
        llm::DreamerTrapState::Waiting,
        "the untyped try's trap still waits"
    );
    assert_eq!(backend.calls(), 0, "no exhausted step called its backend");
    Ok(())
}

/// 6.5d-2: consent, peer and human parks each name their own code-run wait key, admit only a trap
/// consume, ignore an unrelated budget top-up, and wake only on their own delivery: a consent
/// reply, a peer TASK's terminal result, or a human answer.
#[test]
fn consent_peer_and_human_parks_wake_only_on_their_own_delivery()
-> Result<(), Box<dyn std::error::Error>> {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = embedded_owner_proof(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let store = DreamerRunnerStore::new(&vault);
    let actor = WriteActor::new(owner, EdgeActorClass::Human);

    // The asker is the first-party connector actor, the one id the default policy manifest grants
    // an Auto ceiling, so both peer delegations take direct effect instead of parking proposals.
    let asker = EntityId::from_bytes([0xE1; 16]).expect("asker id");
    let peer = EntityId::from_bytes([0xE3; 16]).expect("peer id");
    vault.put_entity(
        &asker,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owen",
    )?;
    vault.put_entity(
        &peer,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"yuki",
    )?;

    // The peer wait ids are two real TASKs a peer is assigned, delegated by the asker. A refusal
    // here stops the fixture: the test never substitutes a fixture delivery for a TASK result.
    let create_now = 1_772_400_000;
    let (receipt_p1, wait_p1) = vault
        .memory(asker, EdgeActorClass::Agent)
        .delegate_task_and_wait(
            &TaskCreateSpec::new(
                rmpv::Value::from("peer delegation p1"),
                None,
                None,
                Some(create_now),
            )
            .with_assignee(TaskAssignee::Peer { actor_ref: peer }),
        )
        .expect("the first peer delegation effects");
    assert!(
        receipt_p1.effected,
        "the first peer delegation takes direct effect"
    );
    assert!(
        receipt_p1.proposal_ref.is_none(),
        "the first peer delegation parks no proposal"
    );
    let task_p1 = receipt_p1
        .task_ref
        .expect("the first peer delegation mints its TASK");
    assert_eq!(
        wait_p1.wait_id, task_p1,
        "the first delegation wait names its TASK"
    );
    let (receipt_p2, wait_p2) = vault
        .memory(asker, EdgeActorClass::Agent)
        .delegate_task_and_wait(
            &TaskCreateSpec::new(
                rmpv::Value::from("peer delegation p2"),
                None,
                None,
                Some(create_now + 1),
            )
            .with_assignee(TaskAssignee::Peer { actor_ref: peer }),
        )
        .expect("the second peer delegation effects");
    assert!(
        receipt_p2.effected,
        "the second peer delegation takes direct effect"
    );
    assert!(
        receipt_p2.proposal_ref.is_none(),
        "the second peer delegation parks no proposal"
    );
    let task_p2 = receipt_p2
        .task_ref
        .expect("the second peer delegation mints its TASK");
    assert_eq!(
        wait_p2.wait_id, task_p2,
        "the second delegation wait names its TASK"
    );

    // Consent and human wait ids are fresh ids; each peer wait id is its TASK ref. Each run id is
    // fresh, and each generation is 0: every wait parks once.
    let key_a = WaitKey {
        run: EntityId::from_bytes([0x61; 16]).expect("run id a"),
        wait_id: EntityId::from_bytes([0xB1; 16]).expect("consent wait id a"),
        generation: 0,
    };
    let key_b = WaitKey {
        run: EntityId::from_bytes([0x62; 16]).expect("run id b"),
        wait_id: EntityId::from_bytes([0xB2; 16]).expect("consent wait id b"),
        generation: 0,
    };
    let key_p1 = WaitKey {
        run: EntityId::from_bytes([0x63; 16]).expect("run id p1"),
        wait_id: task_p1,
        generation: 0,
    };
    let key_p2 = WaitKey {
        run: EntityId::from_bytes([0x64; 16]).expect("run id p2"),
        wait_id: task_p2,
        generation: 0,
    };
    let key_h = WaitKey {
        run: EntityId::from_bytes([0x65; 16]).expect("run id h"),
        wait_id: EntityId::from_bytes([0xB3; 16]).expect("human wait id h"),
        generation: 0,
    };

    let row_a = leased_try(&vault, "park-answer-wait-a", 20)?;
    let row_b = leased_try(&vault, "park-answer-wait-b", 21)?;
    let row_p1 = leased_try(&vault, "park-answer-wait-p1", 22)?;
    let row_p2 = leased_try(&vault, "park-answer-wait-p2", 23)?;
    let row_h = leased_try(&vault, "park-answer-wait-h", 24)?;
    assert_eq!(
        row_a.state.as_str(),
        "leased",
        "try A holds its lease before its step"
    );
    assert_eq!(
        row_b.state.as_str(),
        "leased",
        "try B holds its lease before its step"
    );
    assert_eq!(
        row_p1.state.as_str(),
        "leased",
        "try P1 holds its lease before its step"
    );
    assert_eq!(
        row_p2.state.as_str(),
        "leased",
        "try P2 holds its lease before its step"
    );
    assert_eq!(
        row_h.state.as_str(),
        "leased",
        "try H holds its lease before its step"
    );

    let ctx_a = llm::DurableStepContext {
        vault: &vault,
        attempt_id: row_a.id,
        run_id: None,
        envelope_actor: actor,
        subject: owner,
        deadline: None,
        now_ms: 40_000,
        spend_scope: None,
    };
    let ctx_b = llm::DurableStepContext {
        vault: &vault,
        attempt_id: row_b.id,
        run_id: None,
        envelope_actor: actor,
        subject: owner,
        deadline: None,
        now_ms: 40_001,
        spend_scope: None,
    };
    let ctx_p1 = llm::DurableStepContext {
        vault: &vault,
        attempt_id: row_p1.id,
        run_id: None,
        envelope_actor: actor,
        subject: owner,
        deadline: None,
        now_ms: 40_002,
        spend_scope: None,
    };
    let ctx_p2 = llm::DurableStepContext {
        vault: &vault,
        attempt_id: row_p2.id,
        run_id: None,
        envelope_actor: actor,
        subject: owner,
        deadline: None,
        now_ms: 40_003,
        spend_scope: None,
    };
    let ctx_h = llm::DurableStepContext {
        vault: &vault,
        attempt_id: row_h.id,
        run_id: None,
        envelope_actor: actor,
        subject: owner,
        deadline: None,
        now_ms: 40_004,
        spend_scope: None,
    };
    let step_a = [0xC1; 32];
    let step_b = [0xC2; 32];
    let step_p1 = [0xC3; 32];
    let step_p2 = [0xC4; 32];
    let step_h = [0xC5; 32];

    // Each run parks on its wait before its trap exists, as a dispatched run does before the
    // resident parks its attempt; then the trap opens, waits, and binds beside the park.
    let waiter_a = WaitDeliveries::canonical(&vault).park(&key_a)?;
    assert!(!waiter_a, "try A parks before any reply");
    let trap_a = llm::open_trap(
        &vault,
        &ctx_a,
        llm::DreamerTrapKind::Consent,
        step_a,
        "code-run wait",
    )?;
    assert_eq!(
        trap_a.kind,
        llm::DreamerTrapKind::Consent,
        "try A's trap is a consent trap"
    );
    assert_eq!(
        llm::register_wait(&vault, &trap_a, 50_000)?,
        llm::DreamerTrapState::Waiting,
        "try A's trap waits for its signal"
    );
    let woke_a = park_and_bind_wait_trap(
        &vault,
        ParkDreamerAttempt {
            attempt_id: row_a.id,
            reason: "consent park a".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: llm::trap_park_owner(&trap_a.trap_claim_id),
            carried_spend: None,
            now: 60,
        },
        &key_a,
        &trap_a,
        51_000,
    )?;
    assert!(!woke_a, "try A's park binds with no reply delivered");
    let waiter_b = WaitDeliveries::canonical(&vault).park(&key_b)?;
    assert!(!waiter_b, "try B parks before any reply");
    let trap_b = llm::open_trap(
        &vault,
        &ctx_b,
        llm::DreamerTrapKind::Consent,
        step_b,
        "code-run wait",
    )?;
    assert_eq!(
        trap_b.kind,
        llm::DreamerTrapKind::Consent,
        "try B's trap is a consent trap"
    );
    assert_eq!(
        llm::register_wait(&vault, &trap_b, 50_001)?,
        llm::DreamerTrapState::Waiting,
        "try B's trap waits for its signal"
    );
    let woke_b = park_and_bind_wait_trap(
        &vault,
        ParkDreamerAttempt {
            attempt_id: row_b.id,
            reason: "consent park b".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: llm::trap_park_owner(&trap_b.trap_claim_id),
            carried_spend: None,
            now: 61,
        },
        &key_b,
        &trap_b,
        51_001,
    )?;
    assert!(!woke_b, "try B's park binds with no reply delivered");
    let waiter_p1 = WaitDeliveries::canonical(&vault).park(&key_p1)?;
    assert!(!waiter_p1, "try P1 parks before any reply");
    let trap_p1 = llm::open_trap(
        &vault,
        &ctx_p1,
        llm::DreamerTrapKind::PeerResult,
        step_p1,
        "code-run wait",
    )?;
    assert_eq!(
        trap_p1.kind,
        llm::DreamerTrapKind::PeerResult,
        "try P1's trap is a peer trap"
    );
    assert_eq!(
        llm::register_wait(&vault, &trap_p1, 50_002)?,
        llm::DreamerTrapState::Waiting,
        "try P1's trap waits for its signal"
    );
    let woke_p1 = park_and_bind_wait_trap(
        &vault,
        ParkDreamerAttempt {
            attempt_id: row_p1.id,
            reason: "peer park p1".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: llm::trap_park_owner(&trap_p1.trap_claim_id),
            carried_spend: None,
            now: 62,
        },
        &key_p1,
        &trap_p1,
        51_002,
    )?;
    assert!(!woke_p1, "try P1's park binds with no reply delivered");
    let waiter_p2 = WaitDeliveries::canonical(&vault).park(&key_p2)?;
    assert!(!waiter_p2, "try P2 parks before any reply");
    let trap_p2 = llm::open_trap(
        &vault,
        &ctx_p2,
        llm::DreamerTrapKind::PeerResult,
        step_p2,
        "code-run wait",
    )?;
    assert_eq!(
        trap_p2.kind,
        llm::DreamerTrapKind::PeerResult,
        "try P2's trap is a peer trap"
    );
    assert_eq!(
        llm::register_wait(&vault, &trap_p2, 50_003)?,
        llm::DreamerTrapState::Waiting,
        "try P2's trap waits for its signal"
    );
    let woke_p2 = park_and_bind_wait_trap(
        &vault,
        ParkDreamerAttempt {
            attempt_id: row_p2.id,
            reason: "peer park p2".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: llm::trap_park_owner(&trap_p2.trap_claim_id),
            carried_spend: None,
            now: 63,
        },
        &key_p2,
        &trap_p2,
        51_003,
    )?;
    assert!(!woke_p2, "try P2's park binds with no reply delivered");
    let waiter_h = WaitDeliveries::canonical(&vault).park(&key_h)?;
    assert!(!waiter_h, "try H parks before any reply");
    let trap_h = llm::open_trap(
        &vault,
        &ctx_h,
        llm::DreamerTrapKind::HumanResponse,
        step_h,
        "code-run wait",
    )?;
    assert_eq!(
        trap_h.kind,
        llm::DreamerTrapKind::HumanResponse,
        "try H's trap is a human trap"
    );
    assert_eq!(
        llm::register_wait(&vault, &trap_h, 50_004)?,
        llm::DreamerTrapState::Waiting,
        "try H's trap waits for its signal"
    );
    let woke_h = park_and_bind_wait_trap(
        &vault,
        ParkDreamerAttempt {
            attempt_id: row_h.id,
            reason: "human park h".to_owned(),
            cause: DreamerParkCause::Signal,
            park_owner: llm::trap_park_owner(&trap_h.trap_claim_id),
            carried_spend: None,
            now: 64,
        },
        &key_h,
        &trap_h,
        51_004,
    )?;
    assert!(!woke_h, "try H's park binds with no reply delivered");

    // Each park names its own wait key with its queue generation.
    let park_a = store.parked_attempt(row_a.id)?.expect("try A's park");
    let count_a = store
        .status(row_a.id)?
        .expect("try A's row")
        .attempt
        .attempt_count;
    assert_eq!(
        park_a.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Consent { key: key_a },
            lease_generation: count_a
        }),
        "the consent park names its own wait key"
    );
    assert_eq!(
        park_a.cause,
        DreamerParkCause::Signal,
        "try A's park waits on a signal"
    );
    assert_eq!(
        park_a.park_owner,
        llm::trap_park_owner(&trap_a.trap_claim_id),
        "try A's park sits under its trap's owner"
    );
    assert_eq!(
        count_a, row_a.attempt_count,
        "parking keeps try A's lease generation"
    );
    let park_b = store.parked_attempt(row_b.id)?.expect("try B's park");
    let count_b = store
        .status(row_b.id)?
        .expect("try B's row")
        .attempt
        .attempt_count;
    assert_eq!(
        park_b.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Consent { key: key_b },
            lease_generation: count_b
        }),
        "the second consent park names its own wait key"
    );
    assert_eq!(
        park_b.cause,
        DreamerParkCause::Signal,
        "try B's park waits on a signal"
    );
    assert_eq!(
        park_b.park_owner,
        llm::trap_park_owner(&trap_b.trap_claim_id),
        "try B's park sits under its trap's owner"
    );
    assert_eq!(
        count_b, row_b.attempt_count,
        "parking keeps try B's lease generation"
    );
    let park_p1 = store.parked_attempt(row_p1.id)?.expect("try P1's park");
    let count_p1 = store
        .status(row_p1.id)?
        .expect("try P1's row")
        .attempt
        .attempt_count;
    assert_eq!(
        park_p1.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Peer { key: key_p1 },
            lease_generation: count_p1
        }),
        "the first peer park names its own wait key"
    );
    assert_eq!(
        park_p1.cause,
        DreamerParkCause::Signal,
        "try P1's park waits on a signal"
    );
    assert_eq!(
        park_p1.park_owner,
        llm::trap_park_owner(&trap_p1.trap_claim_id),
        "try P1's park sits under its trap's owner"
    );
    assert_eq!(
        count_p1, row_p1.attempt_count,
        "parking keeps try P1's lease generation"
    );
    let park_p2 = store.parked_attempt(row_p2.id)?.expect("try P2's park");
    let count_p2 = store
        .status(row_p2.id)?
        .expect("try P2's row")
        .attempt
        .attempt_count;
    assert_eq!(
        park_p2.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Peer { key: key_p2 },
            lease_generation: count_p2
        }),
        "the second peer park names its own wait key"
    );
    assert_eq!(
        park_p2.cause,
        DreamerParkCause::Signal,
        "try P2's park waits on a signal"
    );
    assert_eq!(
        park_p2.park_owner,
        llm::trap_park_owner(&trap_p2.trap_claim_id),
        "try P2's park sits under its trap's owner"
    );
    assert_eq!(
        count_p2, row_p2.attempt_count,
        "parking keeps try P2's lease generation"
    );
    let park_h = store.parked_attempt(row_h.id)?.expect("try H's park");
    let count_h = store
        .status(row_h.id)?
        .expect("try H's row")
        .attempt
        .attempt_count;
    assert_eq!(
        park_h.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Human { key: key_h },
            lease_generation: count_h
        }),
        "the human park names its own wait key"
    );
    assert_eq!(
        park_h.cause,
        DreamerParkCause::Signal,
        "try H's park waits on a signal"
    );
    assert_eq!(
        park_h.park_owner,
        llm::trap_park_owner(&trap_h.trap_claim_id),
        "try H's park sits under its trap's owner"
    );
    assert_eq!(
        count_h, row_h.attempt_count,
        "parking keeps try H's lease generation"
    );

    // Only a trap consume resumes an answer-class park; every other resumer stays out.
    for resumer in ParkResumer::ALL {
        assert_eq!(
            park_a.resumable_by(resumer),
            resumer == ParkResumer::TrapConsume,
            "only a trap consume resumes try A's park ({resumer:?})"
        );
    }
    for resumer in ParkResumer::ALL {
        assert_eq!(
            park_b.resumable_by(resumer),
            resumer == ParkResumer::TrapConsume,
            "only a trap consume resumes try B's park ({resumer:?})"
        );
    }
    for resumer in ParkResumer::ALL {
        assert_eq!(
            park_p1.resumable_by(resumer),
            resumer == ParkResumer::TrapConsume,
            "only a trap consume resumes try P1's park ({resumer:?})"
        );
    }
    for resumer in ParkResumer::ALL {
        assert_eq!(
            park_p2.resumable_by(resumer),
            resumer == ParkResumer::TrapConsume,
            "only a trap consume resumes try P2's park ({resumer:?})"
        );
    }
    for resumer in ParkResumer::ALL {
        assert_eq!(
            park_h.resumable_by(resumer),
            resumer == ParkResumer::TrapConsume,
            "only a trap consume resumes try H's park ({resumer:?})"
        );
    }

    // The resume table holds for every cause: under a trap owner only a trap consume admits an
    // answer-class wait, and under every other owner nothing admits one.
    let causes = [
        DreamerParkCause::ProviderUnavailable,
        DreamerParkCause::ExecutorError,
        DreamerParkCause::Checkpoint,
        DreamerParkCause::Retry,
        DreamerParkCause::Paused,
        DreamerParkCause::Cancelled,
        DreamerParkCause::Signal,
        DreamerParkCause::Other,
    ];
    let classes = [
        DreamerParkWaitClass::Consent,
        DreamerParkWaitClass::Peer,
        DreamerParkWaitClass::Human,
    ];
    for cause in causes {
        for class in classes {
            for resumer in ParkResumer::ALL {
                assert_eq!(
                    ParkResume::admits_wait(cause, ParkOwnerClass::Trap, Some(class), resumer),
                    resumer == ParkResumer::TrapConsume,
                    "only a trap consume resumes an answer-class trap park ({cause:?} {class:?} {resumer:?})"
                );
                for owner in ParkOwnerClass::ALL {
                    if owner == ParkOwnerClass::Trap {
                        continue;
                    }
                    assert!(
                        !ParkResume::admits_wait(cause, owner, Some(class), resumer),
                        "no resumer resumes an answer-class park under another owner ({cause:?} {owner:?} {class:?} {resumer:?})"
                    );
                }
            }
        }
    }

    // An unrelated budget top-up leaves all five answer parks parked.
    let scope = SpendScopeId::launch("owen-topup")?;
    let opened = dispatcher
        .open_root_spend_scope(
            scope.clone(),
            DeclaredMaximum {
                units: 100,
                unit: LeaseUnit::tokens(),
            },
            Some(MaximumShown { at_ms: 10_000 }),
            10,
        )
        .expect("the unrelated scope opens");
    assert!(opened.hard, "the unrelated scope is a hard cap");
    assert_eq!(
        opened.state,
        SpendState::Open,
        "the unrelated scope opens open"
    );
    assert_eq!(
        opened.cap_units, 100,
        "the unrelated scope opens under its cap"
    );
    let before_topup_a = store
        .parked_attempt(row_a.id)?
        .expect("try A's park before the top-up");
    let before_topup_b = store
        .parked_attempt(row_b.id)?
        .expect("try B's park before the top-up");
    let before_topup_p1 = store
        .parked_attempt(row_p1.id)?
        .expect("try P1's park before the top-up");
    let before_topup_p2 = store
        .parked_attempt(row_p2.id)?
        .expect("try P2's park before the top-up");
    let before_topup_h = store
        .parked_attempt(row_h.id)?
        .expect("try H's park before the top-up");
    let raised = dispatcher.top_up_spend_scope_as_owner(
        &proof,
        &scope,
        100,
        DeclaredMaximum {
            units: 1_000_000,
            unit: LeaseUnit::tokens(),
        },
        MaximumShown { at_ms: 60_000 },
    )?;
    assert_eq!(raised.cap_units, 1_000_000, "the unrelated top-up lands");
    assert_eq!(
        store.parked_attempt(row_a.id)?,
        Some(before_topup_a),
        "a budget top-up leaves the consent park parked"
    );
    assert_eq!(
        store.parked_attempt(row_b.id)?,
        Some(before_topup_b),
        "a budget top-up leaves the second consent park parked"
    );
    assert_eq!(
        store.parked_attempt(row_p1.id)?,
        Some(before_topup_p1),
        "a budget top-up leaves the first peer park parked"
    );
    assert_eq!(
        store.parked_attempt(row_p2.id)?,
        Some(before_topup_p2),
        "a budget top-up leaves the second peer park parked"
    );
    assert_eq!(
        store.parked_attempt(row_h.id)?,
        Some(before_topup_h),
        "a budget top-up leaves the human park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_a)?,
        llm::DreamerTrapState::Waiting,
        "the top-up leaves try A's trap waiting"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_b)?,
        llm::DreamerTrapState::Waiting,
        "the top-up leaves try B's trap waiting"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_p1)?,
        llm::DreamerTrapState::Waiting,
        "the top-up leaves try P1's trap waiting"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_p2)?,
        llm::DreamerTrapState::Waiting,
        "the top-up leaves try P2's trap waiting"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_h)?,
        llm::DreamerTrapState::Waiting,
        "the top-up leaves try H's trap waiting"
    );

    // B's own delivery wakes only B: A, P1, P2 and H are unchanged and still waiting.
    let park_a_before_b = store
        .parked_attempt(row_a.id)?
        .expect("try A's park before B's delivery");
    let park_p1_before_b = store
        .parked_attempt(row_p1.id)?
        .expect("try P1's park before B's delivery");
    let park_p2_before_b = store
        .parked_attempt(row_p2.id)?
        .expect("try P2's park before B's delivery");
    let park_h_before_b = store
        .parked_attempt(row_h.id)?
        .expect("try H's park before B's delivery");
    let reply_b = serde_json::json!({"answer": "approved"});
    let delivered_b = WaitDeliveries::canonical(&vault).deliver(key_b.wait_id, &reply_b, 80_000)?;
    assert_eq!(
        delivered_b, 1,
        "the consent reply delivers to its one waiter"
    );
    assert!(
        store.parked_attempt(row_b.id)?.is_none(),
        "the consent reply wakes its own park"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_b)?,
        llm::DreamerTrapState::Consumed,
        "the woken consent trap is consumed"
    );
    let status_b = store.status(row_b.id)?.expect("try B's row after the wake");
    assert_eq!(
        status_b.attempt.id, row_b.id,
        "the woken consent try keeps its id"
    );
    assert_eq!(
        status_b.attempt.state.as_str(),
        "queued",
        "the woken consent try queues again"
    );
    assert_eq!(
        status_b.attempt.attempt_count, row_b.attempt_count,
        "the woken consent try keeps its lease generation"
    );
    assert_eq!(
        store.parked_attempt(row_a.id)?,
        Some(park_a_before_b),
        "another consent's delivery leaves the consent park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_a)?,
        llm::DreamerTrapState::Waiting,
        "another consent's delivery leaves the consent trap waiting"
    );
    assert_eq!(
        store.parked_attempt(row_p1.id)?,
        Some(park_p1_before_b),
        "a consent reply leaves the first peer park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_p1)?,
        llm::DreamerTrapState::Waiting,
        "a consent reply leaves the first peer trap waiting"
    );
    assert_eq!(
        store.parked_attempt(row_p2.id)?,
        Some(park_p2_before_b),
        "a consent reply leaves the second peer park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_p2)?,
        llm::DreamerTrapState::Waiting,
        "a consent reply leaves the second peer trap waiting"
    );
    assert_eq!(
        store.parked_attempt(row_h.id)?,
        Some(park_h_before_b),
        "a consent reply leaves the human park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_h)?,
        llm::DreamerTrapState::Waiting,
        "a consent reply leaves the human trap waiting"
    );

    // The peer lands P2's TASK result; P2 wakes while P1, A and H stay parked.
    let park_p1_before_p2 = store
        .parked_attempt(row_p1.id)?
        .expect("try P1's park before P2's result");
    let park_a_before_p2 = store
        .parked_attempt(row_a.id)?
        .expect("try A's park before P2's result");
    let park_h_before_p2 = store
        .parked_attempt(row_h.id)?
        .expect("try H's park before P2's result");
    let result_p2 = EntityId::from_bytes([0xD2; 16]).expect("peer result id p2");
    vault.put_entity(
        &result_p2,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"yuki-result-p2",
    )?;
    vault
        .memory(peer, EdgeActorClass::Agent)
        .land_task_result(
            task_p2,
            &TaskResultInput {
                result_ref: result_p2,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: 1_772_400_100,
            },
        )
        .expect("the peer lands its second result");
    assert!(
        store.parked_attempt(row_p2.id)?.is_none(),
        "the task result wakes its own peer park"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_p2)?,
        llm::DreamerTrapState::Consumed,
        "the woken peer trap is consumed"
    );
    let status_p2 = store
        .status(row_p2.id)?
        .expect("try P2's row after the wake");
    assert_eq!(
        status_p2.attempt.id, row_p2.id,
        "the woken peer try keeps its id"
    );
    assert_eq!(
        status_p2.attempt.state.as_str(),
        "queued",
        "the woken peer try queues again"
    );
    assert_eq!(
        status_p2.attempt.attempt_count, row_p2.attempt_count,
        "the woken peer try keeps its lease generation"
    );
    assert_eq!(
        store.parked_attempt(row_p1.id)?,
        Some(park_p1_before_p2),
        "another task's result leaves the peer park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_p1)?,
        llm::DreamerTrapState::Waiting,
        "another task's result leaves the peer trap waiting"
    );
    assert_eq!(
        store.parked_attempt(row_a.id)?,
        Some(park_a_before_p2),
        "a peer result leaves the consent park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_a)?,
        llm::DreamerTrapState::Waiting,
        "a peer result leaves the consent trap waiting"
    );
    assert_eq!(
        store.parked_attempt(row_h.id)?,
        Some(park_h_before_p2),
        "a peer result leaves the human park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_h)?,
        llm::DreamerTrapState::Waiting,
        "a peer result leaves the human trap waiting"
    );

    // P1's own TASK result wakes P1; H stays parked until its own answer.
    let park_h_before_p1 = store
        .parked_attempt(row_h.id)?
        .expect("try H's park before P1's result");
    let result_p1 = EntityId::from_bytes([0xD1; 16]).expect("peer result id p1");
    vault.put_entity(
        &result_p1,
        ENTITY_TYPE_PERSON,
        TimeRange { start: 1, end: 1 },
        1,
        b"owen-result-p1",
    )?;
    vault
        .memory(peer, EdgeActorClass::Agent)
        .land_task_result(
            task_p1,
            &TaskResultInput {
                result_ref: result_p1,
                disposition: TaskTerminalDisposition::Completed,
                finished_at: 1_772_400_101,
            },
        )
        .expect("the peer lands its first result");
    assert!(
        store.parked_attempt(row_p1.id)?.is_none(),
        "the peer park wakes on its own task's result"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_p1)?,
        llm::DreamerTrapState::Consumed,
        "the first peer trap is consumed"
    );
    let status_p1 = store
        .status(row_p1.id)?
        .expect("try P1's row after the wake");
    assert_eq!(
        status_p1.attempt.id, row_p1.id,
        "the first peer try keeps its id"
    );
    assert_eq!(
        status_p1.attempt.state.as_str(),
        "queued",
        "the first peer try queues again"
    );
    assert_eq!(
        status_p1.attempt.attempt_count, row_p1.attempt_count,
        "the first peer try keeps its lease generation"
    );
    assert_eq!(
        store.parked_attempt(row_h.id)?,
        Some(park_h_before_p1),
        "a peer result leaves the human park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_h)?,
        llm::DreamerTrapState::Waiting,
        "a peer result leaves the human trap waiting"
    );

    // A's own delivery wakes A; H is still parked until its own answer.
    let park_h_before_a = store
        .parked_attempt(row_h.id)?
        .expect("try H's park before A's delivery");
    let reply_a = serde_json::json!({"answer": "approved"});
    let delivered_a = WaitDeliveries::canonical(&vault).deliver(key_a.wait_id, &reply_a, 82_000)?;
    assert_eq!(
        delivered_a, 1,
        "the first consent's reply delivers to its one waiter"
    );
    assert!(
        store.parked_attempt(row_a.id)?.is_none(),
        "the consent park wakes on its own delivery"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_a)?,
        llm::DreamerTrapState::Consumed,
        "the first consent trap is consumed"
    );
    let status_a = store.status(row_a.id)?.expect("try A's row after the wake");
    assert_eq!(
        status_a.attempt.id, row_a.id,
        "the first consent try keeps its id"
    );
    assert_eq!(
        status_a.attempt.state.as_str(),
        "queued",
        "the first consent try queues again"
    );
    assert_eq!(
        status_a.attempt.attempt_count, row_a.attempt_count,
        "the first consent try keeps its lease generation"
    );
    assert_eq!(
        store.parked_attempt(row_h.id)?,
        Some(park_h_before_a),
        "a consent reply leaves the human park parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_h)?,
        llm::DreamerTrapState::Waiting,
        "a consent reply leaves the human trap waiting"
    );

    // H's own delivery wakes H.
    let reply_h = serde_json::json!({"answer": "done"});
    let delivered_h = WaitDeliveries::canonical(&vault).deliver(key_h.wait_id, &reply_h, 84_000)?;
    assert_eq!(
        delivered_h, 1,
        "the human answer delivers to its one waiter"
    );
    assert!(
        store.parked_attempt(row_h.id)?.is_none(),
        "the human park wakes on its own delivery"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap_h)?,
        llm::DreamerTrapState::Consumed,
        "the human trap is consumed"
    );
    let status_h = store.status(row_h.id)?.expect("try H's row after the wake");
    assert_eq!(status_h.attempt.id, row_h.id, "the human try keeps its id");
    assert_eq!(
        status_h.attempt.state.as_str(),
        "queued",
        "the human try queues again"
    );
    assert_eq!(
        status_h.attempt.attempt_count, row_h.attempt_count,
        "the human try keeps its lease generation"
    );
    Ok(())
}

/// The two seats of the 6.5d-3 fixture: neutral ids outside the reserved test-id range.
const SEAT_A_BYTES: [u8; 16] = [0x71; 16];
const SEAT_B_BYTES: [u8; 16] = [0x72; 16];
/// The reset instant both seats report: the vault's recorded now, so the reset has passed with no
/// watcher running, and no other fixture time is fixed.
const SEAT_RESET_T: u64 = 1_000;

/// One unclaimed micro try, so the wake pass leases it under its own owner, as the WAKE-D1
/// `enqueue_micro` fixture does (`tests/wake_d1_park_release.rs`).
fn enqueue_seat_try(
    store: &DreamerRunnerStore<'_>,
    tag: &str,
    now: u64,
) -> oneiron::Result<DreamerAttemptStatus> {
    match store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
        scope: DreamerConsolidationScope::Micro,
        input: rmpv::Value::from(format!("input:{tag}")),
        parent_attempt: None,
        dedupe_key: Some(tag.to_owned()),
        run_id: None,
        now,
    })? {
        EnqueueDreamerAttemptOutcome::Enqueued(status)
        | EnqueueDreamerAttemptOutcome::Existing(status) => Ok(status),
        // The outcome enum is `#[non_exhaustive]` outside the crate.
        other => panic!("unexpected enqueue outcome {other:?}"),
    }
}

/// A server Dreamer pass input at `now`, as `run_input` builds one, leased under the server's
/// park owner so a parked try keeps its lease, as on a running server.
fn seat_run_input(scope: DreamerConsolidationScope, local_node_id: u64, now: u64) -> RunWakePass {
    RunWakePass {
        trigger: WakeTrigger::Compaction,
        scope,
        local_node_id,
        lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
        budget_total_units: 10_000,
        reserve_units: 100,
        now,
        host_scope: None,
        destination_bound: None,
    }
}

/// A frozen pass deadline, as the WAKE-D1 fixture builds one.
fn frozen_deadline(elapsed_ms: u64, ceiling_ms: u64) -> WakePassDeadline {
    let elapsed = Arc::new(AtomicU64::new(elapsed_ms));
    WakePassDeadline::with_clock(ceiling_ms, Arc::new(move || elapsed.load(Ordering::SeqCst)))
}

/// A try's id as the owner's reads spell it: 32 lowercase hex digits.
fn attempt_hex(status: &DreamerAttemptStatus) -> String {
    status
        .attempt
        .id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// A try's lease generation (`attempt_count`), as the owner's reads show it beside its park.
fn attempt_count(
    store: &DreamerRunnerStore<'_>,
    queued: &DreamerAttemptStatus,
) -> oneiron::Result<u32> {
    Ok(store
        .status(queued.attempt.id)?
        .expect("the try")
        .attempt
        .attempt_count)
}

/// A stub seat executor: every admitted try ends refused on its own seat at the fixture reset, so
/// the driver's grouped park write is what the test observes.
struct SeatRefusalStub {
    /// Each admitted try with the seat it refuses on.
    seats: Vec<(AttemptId, [u8; 16])>,
    /// The reset instant every refusal reports.
    reset_at_s: u64,
    /// Admitted tries answered, so a pass that must admit nothing proves it.
    calls: AtomicUsize,
    /// Whether a refusal also raises the pass's cancellation, so the pass stops after it.
    stop_after_refusal: bool,
}

impl SeatRefusalStub {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl DreamerAttemptExecutor for SeatRefusalStub {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        let id = attempt.status.attempt.id;
        let seat = self
            .seats
            .iter()
            .find_map(|(known, seat)| (*known == id).then_some(*seat))
            .expect("the stub refuses every admitted try on its own seat");
        self.calls.fetch_add(1, Ordering::SeqCst);
        let whose = if seat == SEAT_A_BYTES {
            "seat A"
        } else {
            "seat B"
        };
        if self.stop_after_refusal {
            ctx.cancel
                .expect("a driven pass links its cancellation")
                .cancel();
        }
        Ok(DreamerAttemptExecution::ParkOnSeat {
            seat,
            reset_at_s: Some(self.reset_at_s),
            reason: format!("{whose} spent; work parked until {}", self.reset_at_s),
        })
    }
}

/// 6.5d-3: two tries parked on seat A and one on seat B wake only on their own seat's available
/// write: every other resumer refuses, the reset passing alone wakes nothing, the writer for A
/// resumes both A parks in its own write and not B's, a stale generation refuses, the owner's
/// release frees one park, and a later refusal parks again at a new generation.
#[test]
fn seat_parks_wake_only_on_their_own_seat_available_write() -> Result<(), Box<dyn std::error::Error>>
{
    let _store_clock = oneiron_store::ports::manual_clock::ManualClock::new(SEAT_RESET_T);
    let mut config = VaultConfig::device();
    config.store_clock = _store_clock.bundle();
    let (_dir, vault) = open_vault_with(config)?;
    let store = DreamerRunnerStore::new(&vault);
    let proof = embedded_owner_proof(&vault);
    let seat_a = ModelSeatId::from_bytes(SEAT_A_BYTES).expect("seat A id");
    let seat_b = ModelSeatId::from_bytes(SEAT_B_BYTES).expect("seat B id");

    let queued_a1 = enqueue_seat_try(&store, "seat-park-a1", SEAT_RESET_T)?;
    let queued_a2 = enqueue_seat_try(&store, "seat-park-a2", SEAT_RESET_T)?;
    let queued_b1 = enqueue_seat_try(&store, "seat-park-b1", SEAT_RESET_T)?;
    let a1 = queued_a1.attempt.id;
    let a2 = queued_a2.attempt.id;
    let b1 = queued_b1.attempt.id;
    assert!(
        a1 < a2 && a2 < b1,
        "the manual clock mints attempt ids in enqueue order, so one pass parks A1, A2, B1 in order"
    );
    let mut stub = SeatRefusalStub {
        seats: vec![(a1, SEAT_A_BYTES), (a2, SEAT_A_BYTES), (b1, SEAT_B_BYTES)],
        reset_at_s: SEAT_RESET_T,
        calls: AtomicUsize::new(0),
        stop_after_refusal: false,
    };

    // 1. One pass parks all three tries on their seats: A1 and A2 at generations 1 and 2 of seat
    // A, B1 at generation 1 of seat B.
    let node_id = release_doors::load_or_mint_client_id(&vault)?;
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        seat_run_input(DreamerConsolidationScope::Micro, node_id, SEAT_RESET_T),
        &mut stub,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 3, "the pass parks all three tries");
    assert_eq!(report.completed, 0, "no try completes on a spent seat");
    assert_eq!(stub.calls(), 3, "the stub refuses each admitted try once");
    let park_a1 = store.parked_attempt(a1)?.expect("try A1's park");
    let count_a1 = attempt_count(&store, &queued_a1)?;
    assert_eq!(
        park_a1.cause,
        DreamerParkCause::Signal,
        "try A1's seat park waits on a signal"
    );
    assert_eq!(
        park_a1.park_owner, DREAMER_SERVER_PARK_OWNER,
        "try A1's seat park sits under the driver's owner"
    );
    assert_eq!(
        park_a1.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Seat {
                seat: seat_a,
                generation: 1,
                reset_at_s: Some(SEAT_RESET_T),
            },
            lease_generation: count_a1,
        }),
        "try A1's park names seat A at generation 1 with its lease generation"
    );
    assert_eq!(
        store
            .status(a1)?
            .expect("try A1's row")
            .attempt
            .state
            .as_str(),
        "leased",
        "try A1 keeps its lease under its park"
    );
    assert_eq!(
        release_doors::park_notice_seen(&vault, &park_a1)?,
        Some(false),
        "try A1's seat park raises the owner's notice"
    );
    let park_a2 = store.parked_attempt(a2)?.expect("try A2's park");
    let count_a2 = attempt_count(&store, &queued_a2)?;
    assert_eq!(
        park_a2.cause,
        DreamerParkCause::Signal,
        "try A2's seat park waits on a signal"
    );
    assert_eq!(
        park_a2.park_owner, DREAMER_SERVER_PARK_OWNER,
        "try A2's seat park sits under the driver's owner"
    );
    assert_eq!(
        park_a2.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Seat {
                seat: seat_a,
                generation: 2,
                reset_at_s: Some(SEAT_RESET_T),
            },
            lease_generation: count_a2,
        }),
        "try A2's park names seat A at generation 2 with its lease generation"
    );
    assert_eq!(
        store
            .status(a2)?
            .expect("try A2's row")
            .attempt
            .state
            .as_str(),
        "leased",
        "try A2 keeps its lease under its park"
    );
    assert_eq!(
        release_doors::park_notice_seen(&vault, &park_a2)?,
        Some(false),
        "try A2's seat park raises the owner's notice"
    );
    let park_b1 = store.parked_attempt(b1)?.expect("try B1's park");
    let count_b1 = attempt_count(&store, &queued_b1)?;
    assert_eq!(
        park_b1.cause,
        DreamerParkCause::Signal,
        "try B1's seat park waits on a signal"
    );
    assert_eq!(
        park_b1.park_owner, DREAMER_SERVER_PARK_OWNER,
        "try B1's seat park sits under the driver's owner"
    );
    assert_eq!(
        park_b1.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Seat {
                seat: seat_b,
                generation: 1,
                reset_at_s: Some(SEAT_RESET_T),
            },
            lease_generation: count_b1,
        }),
        "try B1's park names seat B at generation 1 with its lease generation"
    );
    assert_eq!(
        store
            .status(b1)?
            .expect("try B1's row")
            .attempt
            .state
            .as_str(),
        "leased",
        "try B1 keeps its lease under its park"
    );
    assert_eq!(
        release_doors::park_notice_seen(&vault, &park_b1)?,
        Some(false),
        "try B1's seat park raises the owner's notice"
    );
    let state_a = vault.model_seat_state(seat_a)?.expect("seat A's row");
    assert_eq!(
        state_a.availability,
        ModelSeatAvailability::Unavailable,
        "seat A is unavailable after its refusals"
    );
    assert_eq!(
        state_a.generation, 2,
        "seat A's second refusal parks it at generation 2"
    );
    assert_eq!(
        state_a.reset_at_s,
        Some(SEAT_RESET_T),
        "seat A keeps its reported reset"
    );
    let state_b = vault.model_seat_state(seat_b)?.expect("seat B's row");
    assert_eq!(
        state_b.availability,
        ModelSeatAvailability::Unavailable,
        "seat B is unavailable after its refusal"
    );
    assert_eq!(
        state_b.generation, 1,
        "seat B's refusal parks it at generation 1"
    );
    assert_eq!(
        state_b.reset_at_s,
        Some(SEAT_RESET_T),
        "seat B keeps its reported reset"
    );
    assert_eq!(
        vault.next_model_seat_reset_due()?,
        Some(SEAT_RESET_T),
        "both seats' resets are due"
    );

    // 2. Only their seat's available write or the owner's release resumes a seat park; every other
    // resumer refuses, and a later pass with no write leaves all three parked.
    for resumer in ParkResumer::ALL {
        let admitted =
            resumer == ParkResumer::SeatAvailable || resumer == ParkResumer::OwnerRelease;
        assert_eq!(
            park_a1.resumable_by(resumer),
            admitted,
            "only its seat's available write or the owner's release resumes try A1's park ({resumer:?})"
        );
    }
    for resumer in ParkResumer::ALL {
        let admitted =
            resumer == ParkResumer::SeatAvailable || resumer == ParkResumer::OwnerRelease;
        assert_eq!(
            park_a2.resumable_by(resumer),
            admitted,
            "only its seat's available write or the owner's release resumes try A2's park ({resumer:?})"
        );
    }
    for resumer in ParkResumer::ALL {
        let admitted =
            resumer == ParkResumer::SeatAvailable || resumer == ParkResumer::OwnerRelease;
        assert_eq!(
            park_b1.resumable_by(resumer),
            admitted,
            "only its seat's available write or the owner's release resumes try B1's park ({resumer:?})"
        );
    }
    let causes = [
        DreamerParkCause::ProviderUnavailable,
        DreamerParkCause::ExecutorError,
        DreamerParkCause::Checkpoint,
        DreamerParkCause::Retry,
        DreamerParkCause::Paused,
        DreamerParkCause::Cancelled,
        DreamerParkCause::Signal,
        DreamerParkCause::Other,
    ];
    for cause in causes {
        for owner in ParkOwnerClass::ALL {
            for resumer in ParkResumer::ALL {
                assert_eq!(
                    ParkResume::admits_wait(
                        cause,
                        owner,
                        Some(DreamerParkWaitClass::Seat),
                        resumer
                    ),
                    resumer == ParkResumer::SeatAvailable || resumer == ParkResumer::OwnerRelease,
                    "a seat wait admits only its seat-available write or the owner's release, under any owner ({cause:?} {owner:?} {resumer:?})"
                );
            }
        }
    }
    let other_waits = [
        None,
        Some(DreamerParkWaitClass::Budget),
        Some(DreamerParkWaitClass::Consent),
        Some(DreamerParkWaitClass::Peer),
        Some(DreamerParkWaitClass::Human),
    ];
    for wait in other_waits {
        for cause in causes {
            for owner in ParkOwnerClass::ALL {
                assert!(
                    !ParkResume::admits_wait(cause, owner, wait, ParkResumer::SeatAvailable),
                    "the seat-available resumer admits no wait but a seat wait ({wait:?} {cause:?} {owner:?})"
                );
            }
        }
    }
    let calls_before_pass = stub.calls();
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        seat_run_input(DreamerConsolidationScope::Micro, node_id, SEAT_RESET_T),
        &mut stub,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(
        report.parked, 0,
        "a later pass parks nothing new without a write"
    );
    assert_eq!(
        report.completed, 0,
        "a later pass completes nothing without a write"
    );
    assert_eq!(
        stub.calls(),
        calls_before_pass,
        "a later pass does not run a seat-parked try"
    );
    assert_eq!(
        store.parked_attempt(a1)?,
        Some(park_a1.clone()),
        "a later pass leaves try A1's seat park parked"
    );
    assert_eq!(
        store.parked_attempt(a2)?,
        Some(park_a2.clone()),
        "a later pass leaves try A2's seat park parked"
    );
    assert_eq!(
        store.parked_attempt(b1)?,
        Some(park_b1.clone()),
        "a later pass leaves try B1's seat park parked"
    );

    // 3. The owner's release of A2 wakes only A2 and resolves its notice; the next pass claims A2
    // again and its next refusal parks it at generation 3.
    let released = release_doors::release_as_owner(
        &vault,
        &proof,
        &attempt_hex(&queued_a2),
        DreamerParkCauseView::Signal,
        park_a2.parked_at,
        attempt_count(&store, &queued_a2)?,
    )?;
    assert_eq!(
        released.cause, "signal",
        "the release receipts try A2's signal park"
    );
    assert!(
        store.parked_attempt(a2)?.is_none(),
        "the owner's release wakes only the park it names"
    );
    let status_a2 = store.status(a2)?.expect("try A2's row after its release");
    assert_eq!(status_a2.attempt.id, a2, "the released try keeps its id");
    assert_eq!(
        status_a2.attempt.state.as_str(),
        "queued",
        "the released try queues again"
    );
    assert_eq!(
        status_a2.attempt.attempt_count, count_a2,
        "the released try keeps its lease generation"
    );
    assert_eq!(
        store.parked_attempt(a1)?,
        Some(park_a1.clone()),
        "the release of A2 leaves try A1's seat park parked"
    );
    assert_eq!(
        store.parked_attempt(b1)?,
        Some(park_b1.clone()),
        "the release of A2 leaves try B1's seat park parked"
    );
    assert_eq!(
        release_doors::park_notice_seen(&vault, &park_a2)?,
        Some(true),
        "the release resolves try A2's notice"
    );
    let calls_before_repark = stub.calls();
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        seat_run_input(DreamerConsolidationScope::Micro, node_id, SEAT_RESET_T),
        &mut stub,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 1, "the next pass parks try A2 again");
    assert_eq!(
        stub.calls(),
        calls_before_repark + 1,
        "the next pass runs only the released try"
    );
    let park_a2 = store.parked_attempt(a2)?.expect("try A2's second park");
    let count_a2 = attempt_count(&store, &queued_a2)?;
    assert_eq!(
        park_a2.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Seat {
                seat: seat_a,
                generation: 3,
                reset_at_s: Some(SEAT_RESET_T),
            },
            lease_generation: count_a2,
        }),
        "try A2's next refusal parks it again at generation 3"
    );
    let state_a = vault.model_seat_state(seat_a)?.expect("seat A's row");
    assert_eq!(
        state_a.availability,
        ModelSeatAvailability::Unavailable,
        "seat A is unavailable after try A2's next refusal"
    );
    assert_eq!(
        state_a.generation, 3,
        "try A2's next refusal parks seat A at generation 3"
    );
    assert_eq!(
        release_doors::park_notice_seen(&vault, &park_a2)?,
        Some(false),
        "try A2's second park raises the owner's notice again"
    );

    // 4. An available write answering the older generation 2 is refused: nothing resumes.
    let stale = vault.record_model_seat_available(seat_a, 2, ModelSeatAvailableSource::ResetPassed);
    assert!(
        stale.is_err(),
        "an available write answering an older generation is refused"
    );
    assert_eq!(
        store.parked_attempt(a1)?,
        Some(park_a1.clone()),
        "a refused available write leaves try A1 parked"
    );
    assert_eq!(
        store.parked_attempt(a2)?,
        Some(park_a2.clone()),
        "a refused available write leaves try A2 parked"
    );
    assert_eq!(
        store.parked_attempt(b1)?,
        Some(park_b1.clone()),
        "a refused available write leaves try B1 parked"
    );
    let state_a = vault.model_seat_state(seat_a)?.expect("seat A's row");
    assert_eq!(
        state_a.availability,
        ModelSeatAvailability::Unavailable,
        "a refused available write leaves seat A unavailable"
    );
    assert_eq!(
        state_a.generation, 3,
        "a refused available write leaves seat A at generation 3"
    );

    // 5. The writer at generation 3 resumes every park of seat A in its own write and not B's.
    // The ruled option is the writer, not the sweep: the sweep would also release due seat B.
    vault.record_model_seat_available(seat_a, 3, ModelSeatAvailableSource::ResetPassed)?;
    assert!(
        store.parked_attempt(a1)?.is_none(),
        "the seat-available write resumes every park of its seat in its own write"
    );
    assert!(
        store.parked_attempt(a2)?.is_none(),
        "the same write resumes the seat's second park too"
    );
    let status_a1 = store.status(a1)?.expect("try A1's row after the wake");
    assert_eq!(status_a1.attempt.id, a1, "the woken try A1 keeps its id");
    assert_eq!(
        status_a1.attempt.state.as_str(),
        "queued",
        "the woken try A1 queues again"
    );
    assert_eq!(
        status_a1.attempt.attempt_count, count_a1,
        "the woken try A1 keeps its lease generation"
    );
    let status_a2 = store.status(a2)?.expect("try A2's row after the wake");
    assert_eq!(status_a2.attempt.id, a2, "the woken try A2 keeps its id");
    assert_eq!(
        status_a2.attempt.state.as_str(),
        "queued",
        "the woken try A2 queues again"
    );
    assert_eq!(
        status_a2.attempt.attempt_count, count_a2,
        "the woken try A2 keeps its lease generation"
    );
    assert_eq!(
        store.parked_attempt(b1)?,
        Some(park_b1.clone()),
        "the seat-available write for A leaves try B1's seat park parked"
    );
    let state_a = vault.model_seat_state(seat_a)?.expect("seat A's row");
    assert_eq!(
        state_a.availability,
        ModelSeatAvailability::Available,
        "seat A is available after its own write"
    );
    assert_eq!(
        state_a.generation, 3,
        "seat A's available write answers generation 3"
    );
    assert_eq!(
        vault.next_model_seat_reset_due()?,
        Some(SEAT_RESET_T),
        "seat A's due entry is gone; seat B's reset is next"
    );
    assert_eq!(
        release_doors::park_notice_seen(&vault, &park_a1)?,
        Some(true),
        "the seat-available write resolves try A1's notice"
    );
    assert_eq!(
        release_doors::park_notice_seen(&vault, &park_a2)?,
        Some(true),
        "the seat-available write resolves try A2's notice"
    );
    assert_eq!(
        release_doors::park_notice_seen(&vault, &park_b1)?,
        Some(false),
        "try B1's notice stays raised"
    );

    // 6. A second available write for the same generation is refused.
    let again = vault.record_model_seat_available(seat_a, 3, ModelSeatAvailableSource::ResetPassed);
    assert!(
        again.is_err(),
        "a second available write for the same generation is refused"
    );
    assert_eq!(
        store
            .status(a1)?
            .expect("try A1's row")
            .attempt
            .state
            .as_str(),
        "queued",
        "the refused second write leaves try A1 queued"
    );
    assert_eq!(
        store
            .status(a2)?
            .expect("try A2's row")
            .attempt
            .state
            .as_str(),
        "queued",
        "the refused second write leaves try A2 queued"
    );
    assert_eq!(
        store.parked_attempt(b1)?,
        Some(park_b1.clone()),
        "the refused second write leaves try B1 parked"
    );
    let state_a = vault.model_seat_state(seat_a)?.expect("seat A's row");
    assert_eq!(
        state_a.availability,
        ModelSeatAvailability::Available,
        "the refused second write leaves seat A available"
    );
    assert_eq!(
        state_a.generation, 3,
        "the refused second write leaves seat A at generation 3"
    );

    // 7. A later refusal on A1 parks again at generation 4, which the older answered
    // generation no longer wakes; the stub's cancellation stops the pass after that one
    // refusal, so A2 stays queued and B1 stays parked.
    stub.stop_after_refusal = true;
    let calls_before_final = stub.calls();
    let final_cancel = WakeCancellation::new();
    let mut driver = DreamerWakeDriver::new(&vault, "wake", frozen_deadline(0, 180_000));
    let report = block_on_ready(driver.run_wake_pass(
        seat_run_input(DreamerConsolidationScope::Micro, node_id, SEAT_RESET_T),
        &mut stub,
        &final_cancel,
    ))?;
    assert_eq!(
        report.parked, 1,
        "the final pass parks only the first queued try"
    );
    assert_eq!(
        stub.calls(),
        calls_before_final + 1,
        "the final pass runs only the first queued try"
    );
    assert_eq!(
        report.stop,
        WakePassStop::Cancelled,
        "the stub's cancellation stops the pass after its refusal"
    );
    let park_a1 = store.parked_attempt(a1)?.expect("try A1's second park");
    let count_a1 = attempt_count(&store, &queued_a1)?;
    assert_eq!(
        park_a1.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Seat {
                seat: seat_a,
                generation: 4,
                reset_at_s: Some(SEAT_RESET_T),
            },
            lease_generation: count_a1,
        }),
        "try A1's later refusal parks it again at generation 4"
    );
    let state_a = vault.model_seat_state(seat_a)?.expect("seat A's row");
    assert_eq!(
        state_a.availability,
        ModelSeatAvailability::Unavailable,
        "seat A is unavailable after the later refusal"
    );
    assert_eq!(
        state_a.generation, 4,
        "seat A's row answers the latest refusal"
    );
    let stale_login =
        vault.record_model_seat_available(seat_a, 3, ModelSeatAvailableSource::LoginRestored);
    assert!(
        stale_login.is_err(),
        "an available write answering generation 3 after a later refusal is refused"
    );
    assert_eq!(
        store.parked_attempt(a1)?,
        Some(park_a1),
        "the refused login-restored write leaves try A1 parked"
    );
    assert!(
        store.parked_attempt(a2)?.is_none(),
        "the final pass never parks try A2"
    );
    assert_eq!(
        store
            .status(a2)?
            .expect("try A2's row")
            .attempt
            .state
            .as_str(),
        "queued",
        "try A2 stays queued"
    );
    assert_eq!(
        store.parked_attempt(b1)?,
        Some(park_b1),
        "a login-restored write for A leaves try B1 parked"
    );
    Ok(())
}
