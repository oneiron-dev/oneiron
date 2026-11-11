//! 6.5d-1 (budget typed wait): a step refused by its spend scope's hard cap parks typed on that
//! scope, and only that scope's room-leaving top-up wakes it.
//!
//! Tries A and B run under `guard_for_scope` guards of two hard root scopes whose caps sit well
//! below the guards' reserve; try C runs scopeless under a zero-limit guard. Each step goes through
//! the public `call_as_step` with a paid request and a backend that must not be called. Trap head
//! states read through `oneiron::test_doors::park_typed_wait`, built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId, SpendState};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DreamerConsolidationScope, DreamerParkWait,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    ParkResumer,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::test_doors::park_typed_wait as doors;
use oneiron::{DreamerParkCause, Vault, VaultConfig, WriteActor};

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

/// 6.5d-1 review: a soft child scope's step that its hard root refuses parks on the root, asking
/// the root only for what the child's own hold cannot cover; a root top-up short of that deficit
/// wakes nothing, and one that covers it wakes the child, though the root alone still holds less
/// than the whole reservation.
#[test]
fn a_soft_childs_budget_wait_asks_its_hard_root_only_for_the_deficit()
-> Result<(), Box<dyn std::error::Error>> {
    let (_dir, vault) = open_vault()?;
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let proof = embedded_owner_proof(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let store = DreamerRunnerStore::new(&vault);

    // The child holds half of the default reserve from its hard root; the root keeps a sliver.
    let reserve = llm::BudgetGuard::new(
        "park-typed-wait-reserve",
        0,
        llm::BudgetExhaustionPolicy::Suspend,
    )
    .reserve_units();
    let hold = reserve / 2;
    let deficit = reserve - hold;
    let sliver = 10;
    assert!(
        0 < hold && sliver < deficit,
        "the root's sliver cannot cover the child's deficit"
    );
    let root = SpendScopeId::launch("owen-root")?;
    let opened = dispatcher
        .open_root_spend_scope(
            root.clone(),
            DeclaredMaximum {
                units: hold + sliver,
                unit: LeaseUnit::tokens(),
            },
            Some(MaximumShown { at_ms: 12_000 }),
            12,
        )
        .expect("the hard root opens");
    assert!(opened.hard, "the root is a hard cap");
    assert_eq!(opened.state, SpendState::Open, "the root opens open");

    let row = leased_try(&vault, "park-typed-wait-child", 23)?;
    assert_eq!(
        row.state.as_str(),
        "leased",
        "the child's try holds its lease before its step"
    );
    let child = doors::reserve_child_hold_scope(&vault, &root, &row.id, hold, 24)?;
    assert!(!child.hard, "the child's hold is soft");
    assert_eq!(
        child.state,
        SpendState::Open,
        "the child's scope opens open"
    );
    assert_eq!(
        child.parent.as_ref(),
        Some(&root),
        "the child's scope sits under the root"
    );
    assert_eq!(child.cap_units, hold, "the child holds half the reserve");
    assert_eq!(
        dispatcher.available_units(&child.scope)?,
        hold + sliver,
        "the child may spend its hold and the root's sliver"
    );
    let guard = dispatcher.guard_for_scope(&child.scope)?;
    assert_eq!(
        guard.reserve_units(),
        reserve,
        "the child's guard reserves the default"
    );

    let actor = WriteActor::new(owner, EdgeActorClass::Human);
    let ctx = llm::DurableStepContext {
        vault: &vault,
        attempt_id: row.id,
        run_id: None,
        envelope_actor: actor,
        subject: owner,
        deadline: None,
        now_ms: 43_000,
        spend_scope: Some(child.scope.clone()),
    };
    let backend = NeverBackend::new();
    let outcome = block_on_ready(llm::call_as_step(
        &ctx,
        &backend,
        &guard,
        paid_step_request("park typed wait child"),
    ))
    .expect("the child's step answers");
    let llm::StepOutcome::Trapped { trap, .. } = outcome else {
        panic!("the child's spent budget traps its step");
    };
    assert_eq!(
        trap.kind,
        llm::DreamerTrapKind::Budget,
        "the child's trap is a budget trap"
    );
    assert_eq!(
        llm::register_wait(&vault, &trap, 53_000)?,
        llm::DreamerTrapState::Waiting,
        "the child's trap waits for its signal"
    );
    let park = store.parked_attempt(row.id)?.expect("the child's park");
    let Some(wait) = park.wait.clone() else {
        panic!("the child's park carries a typed wait");
    };
    assert!(
        matches!(&wait.wait, DreamerParkWait::Budget { scope, .. } if scope == &root),
        "the child's wait names its hard root, whose own cap refused"
    );
    assert_eq!(
        wait.lease_generation, row.attempt_count,
        "the child's wait stamps its queue generation"
    );

    // A root top-up one unit short of the deficit wakes nothing.
    let short_cap = hold + deficit - 1;
    let raised = dispatcher.top_up_spend_scope_as_owner(
        &proof,
        &root,
        hold + sliver,
        DeclaredMaximum {
            units: short_cap,
            unit: LeaseUnit::tokens(),
        },
        MaximumShown { at_ms: 80_000 },
    )?;
    assert_eq!(raised.cap_units, short_cap, "the root's short top-up lands");
    assert!(
        store.parked_attempt(row.id)?.is_some(),
        "a root top-up short of the deficit leaves the child parked"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap)?,
        llm::DreamerTrapState::Waiting,
        "a root top-up short of the deficit leaves the child's trap waiting"
    );

    // A root top-up that covers the deficit wakes the child, though the root alone still holds less
    // than the whole reservation.
    let deficit_cap = hold + deficit;
    let raised = dispatcher.top_up_spend_scope_as_owner(
        &proof,
        &root,
        short_cap,
        DeclaredMaximum {
            units: deficit_cap,
            unit: LeaseUnit::tokens(),
        },
        MaximumShown { at_ms: 90_000 },
    )?;
    assert_eq!(
        raised.cap_units, deficit_cap,
        "the root's deficit top-up lands"
    );
    assert_eq!(
        dispatcher.available_units(&child.scope)?,
        reserve,
        "the child may now spend the whole reservation"
    );
    assert!(
        dispatcher.available_units(&root)? < reserve,
        "the root alone still holds less than the whole reservation"
    );
    assert!(
        store.parked_attempt(row.id)?.is_none(),
        "a root top-up that covers the child's deficit wakes the child's try"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap)?,
        llm::DreamerTrapState::Consumed,
        "the woken child's trap is consumed"
    );
    let status = store
        .status(row.id)?
        .expect("the child's row after the wake");
    assert_eq!(
        status.attempt.state.as_str(),
        "queued",
        "the woken child queues again"
    );
    assert_eq!(
        wait.wait,
        DreamerParkWait::Budget {
            scope: root.clone(),
            asked_units: deficit,
        },
        "the child's wait asked its root only for the deficit"
    );
    assert_eq!(
        backend.calls(),
        0,
        "the refused step never called its backend"
    );
    Ok(())
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
