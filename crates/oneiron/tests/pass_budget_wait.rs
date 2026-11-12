//! Row B2 of BUDGET-TRAP-UNTYPED-NO-SENDER: a step's spent budget waits on the write that refills
//! it, or refuses when no write does.
//!
//! - A step bound to its wake pass (every Dreamer host) whose guard is spent parks a `PassBudget`
//!   wait. A later pass whose guard has room for it wakes the park at the pass's start, oldest
//!   first, each woken park taking its asked units from the room; a pass still short leaves it.
//! - The owner frees a park at its budget trap through `vault.runs.parks.release`: Resume wakes
//!   the trap, so the try queues again as the same try; Stop wakes the trap and ends the try. Both
//!   serve a `PassBudget` wait and a spend scope's `Budget` wait.
//! - A step bound to neither a wake pass nor a spend scope (the owner's own model step, a run
//!   host's media step) refuses `Unbound`, typed, and parks nothing.
//!
//! Each step goes through the public `call_as_step` with a paid request and a backend that must
//! not be called. Trap states and the owner's release go through `oneiron::test_doors`, built only
//! under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test pass_budget_wait`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DREAMER_SERVER_PARK_OWNER, DreamerConsolidationScope,
    DreamerParkWait, DreamerParkedWait, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt, ParkResumer,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::memory::DreamerParkCauseView;
use oneiron::store::model_step_submission::StepBudgetRefusal;
use oneiron::test_doors::park_typed_wait as doors;
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{
    DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor, DreamerParkCause,
    DreamerWakeDriver, RunWakePass, Vault, VaultConfig, WakeAttemptContext, WakeCancellation,
    WakePassDeadline, WakeTrigger, WriteActor,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The reserve of every step guard here: what a refused reservation asks.
const STEP_RESERVE: u64 = 500;
/// A hard root cap well below the step reserve.
const ROOT_CAP: u64 = 100;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // A spent step answers without parking the thread, and a wake pass yields only at its
    // attempt boundaries, so polling again immediately is correct; the bound catches a future
    // pending on anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("a pass budget future pending on something other than an attempt-boundary yield");
}

/// A temporary vault with a process-memory device keystore, as the crate's test opener opens one.
fn open_vault() -> oneiron::Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Ok((dir, vault))
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

/// One paid model request on the owner's own server, so a guard admits it on its paid line and a
/// spent line refuses it.
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
        panic!("a spent step must not call its backend");
    }

    fn stream<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmStreamResult<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("a spent step must not call its backend");
    }
}

/// One micro consolidation try enqueued under `tag` and claimed under the Dreamer server's lease
/// owner, as a running server's pass holds it, so its step parks under a live lease.
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
    let ClaimOutcome::Claimed(row) = AttemptQueue::new(vault).claim_kind(
        DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND,
        ClaimAttempt {
            lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
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

/// A spent step guard: no room, the fixture's reserve.
fn spent_guard(name: &str) -> llm::BudgetGuard {
    llm::BudgetGuard::with_reserve_units(
        name,
        0,
        STEP_RESERVE,
        llm::BudgetExhaustionPolicy::Suspend,
    )
}

/// Runs one paid step of `row`'s try under a spent guard, bound to its wake pass or to nothing.
fn spent_step(
    vault: &Vault,
    row: &AttemptRecord,
    wake_pass_bound: bool,
    now_ms: u64,
    backend: &NeverBackend,
) -> llm::DurableStepResult<llm::StepOutcome> {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let ctx = llm::DurableStepContext {
        vault,
        attempt_id: row.id,
        run_id: None,
        envelope_actor: WriteActor::new(owner, EdgeActorClass::Human),
        subject: owner,
        deadline: None,
        now_ms,
        spend_scope: None,
        wake_pass_bound,
    };
    let guard = spent_guard("pass-budget-wait-step");
    block_on_ready(llm::call_as_step(
        &ctx,
        backend,
        &guard,
        paid_step_request("pass budget wait"),
    ))
}

/// Parks `row`'s try on its pass: its pass-bound step's spent guard traps it. Returns its trap.
fn park_on_pass(
    vault: &Vault,
    row: &AttemptRecord,
    now_ms: u64,
    backend: &NeverBackend,
) -> Result<llm::TrapRef, Box<dyn std::error::Error>> {
    let outcome = spent_step(vault, row, true, now_ms, backend).expect("the pass step answers");
    let llm::StepOutcome::Trapped { trap, .. } = outcome else {
        panic!("a pass step's spent guard traps the step: got {outcome:?}");
    };
    assert_eq!(
        trap.kind,
        llm::DreamerTrapKind::Budget,
        "the spent pass step's trap is a budget trap"
    );
    Ok(trap)
}

/// Asserts `row`'s try parks on its pass at its trap, asking the step reserve.
fn assert_pass_budget_park(
    store: &DreamerRunnerStore<'_>,
    row: &AttemptRecord,
    trap: &llm::TrapRef,
) -> TestResult {
    let park = store.parked_attempt(row.id)?.expect("the pass step's park");
    assert_eq!(
        park.park_owner,
        llm::trap_park_owner(&trap.trap_claim_id),
        "the pass step's park sits under its trap's owner"
    );
    assert_eq!(
        park.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::PassBudget {
                asked_units: STEP_RESERVE,
                scope: None,
            },
            lease_generation: row.attempt_count,
        }),
        "a pass step's spent guard parks a pass budget wait asking its reserve"
    );
    // A top-up wakes only a pass budget wait that names its scope; this one names none.
    for resumer in [ParkResumer::LaterPass, ParkResumer::BootRecovery] {
        assert!(
            !park.resumable_by(resumer),
            "a pass budget park admits no {resumer:?}"
        );
    }
    assert!(
        park.resumable_by(ParkResumer::PassStart),
        "a pass start may wake a pass budget park"
    );
    Ok(())
}

/// Asserts `row`'s try was woken as the same try: its park gone, its trap consumed, queued again
/// under the same lease generation.
fn assert_woken(vault: &Vault, row: &AttemptRecord, trap: &llm::TrapRef, what: &str) -> TestResult {
    let store = DreamerRunnerStore::new(vault);
    assert!(
        store.parked_attempt(row.id)?.is_none(),
        "{what} clears the park"
    );
    assert_eq!(
        doors::trap_state(vault, trap)?,
        llm::DreamerTrapState::Consumed,
        "{what} consumes the park's trap"
    );
    let status = store.status(row.id)?.expect("the woken try's row");
    assert_eq!(
        status.attempt.state.as_str(),
        "queued",
        "{what} queues the same try again"
    );
    assert_eq!(
        status.attempt.attempt_count, row.attempt_count,
        "{what} keeps the try's lease generation"
    );
    Ok(())
}

/// A frozen pass deadline, as the WAKE-D1 fixture builds one.
fn frozen_deadline() -> WakePassDeadline {
    let elapsed = Arc::new(AtomicU64::new(0));
    WakePassDeadline::with_clock(180_000, Arc::new(move || elapsed.load(Ordering::SeqCst)))
}

/// An executor that must run nothing: the passes here are macro passes, and every try is micro.
struct NoAttempt;

impl DreamerAttemptExecutor for NoAttempt {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        panic!(
            "a macro pass admits no micro try: admitted {:?}",
            attempt.status.attempt.id
        );
    }
}

/// Runs one server Dreamer pass at `now` whose guard has `room_units`. It is a macro pass, so the
/// micro tries its start wakes stay queued for the test to read.
fn run_pass(vault: &Vault, pass: u64, room_units: u64, now: u64) -> TestResult {
    let guard = llm::BudgetGuard::with_reserve_units(
        format!("pass-budget-wait:p{pass}"),
        room_units,
        100,
        llm::BudgetExhaustionPolicy::Suspend,
    );
    let node_id = release_doors::load_or_mint_client_id(vault)?;
    let mut driver =
        DreamerWakeDriver::new(vault, "wake", frozen_deadline()).with_budget_guard(guard);
    block_on_ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Macro,
            local_node_id: node_id,
            lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            now,
            host_scope: None,
            destination_bound: None,
        },
        &mut NoAttempt,
        &WakeCancellation::new(),
    ))?;
    Ok(())
}

/// A try's id as the owner's reads spell it: 32 lowercase hex digits.
fn attempt_hex(row: &AttemptRecord) -> String {
    row.id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Opens a hard root of `units`, shown at its start.
fn open_root(
    dispatcher: &AgentDispatcher<'_>,
    name: &str,
    units: u64,
) -> Result<SpendScopeId, Box<dyn std::error::Error>> {
    let root = SpendScopeId::launch(name)?;
    let opened = dispatcher.open_root_spend_scope(
        root.clone(),
        DeclaredMaximum {
            units,
            unit: LeaseUnit::tokens(),
        },
        Some(MaximumShown { at_ms: 12_000 }),
        12,
    )?;
    assert!(opened.hard, "the root is a hard cap");
    Ok(root)
}

/// Parks `row`'s try on a hard root of its own whose cap sits below the guard's reserve: a spend
/// scope's `Budget` wait at its trap. Returns its trap.
fn park_on_scope(
    vault: &Vault,
    row: &AttemptRecord,
    name: &str,
    now_ms: u64,
    backend: &NeverBackend,
) -> Result<llm::TrapRef, Box<dyn std::error::Error>> {
    let dispatcher = AgentDispatcher::new(vault);
    let root = open_root(&dispatcher, name, ROOT_CAP)?;
    let spend = llm::StepSpendScope::read_before_guards(vault, root.clone())?;
    let guard = dispatcher.guard_for_scope(&root)?;
    assert!(
        ROOT_CAP < guard.reserve_units(),
        "the root's cap sits below the guard's reserve"
    );
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let ctx = llm::DurableStepContext {
        vault,
        attempt_id: row.id,
        run_id: None,
        envelope_actor: WriteActor::new(owner, EdgeActorClass::Human),
        subject: owner,
        deadline: None,
        now_ms,
        spend_scope: Some(spend),
        wake_pass_bound: false,
    };
    let outcome = block_on_ready(llm::call_as_step(
        &ctx,
        backend,
        &guard,
        paid_step_request("scope budget wait"),
    ))
    .expect("the scope step answers");
    let llm::StepOutcome::Trapped { trap, .. } = outcome else {
        panic!("a scope step its hard root refuses traps the step: got {outcome:?}");
    };
    let park = DreamerRunnerStore::new(vault)
        .parked_attempt(row.id)?
        .expect("the scope step's park");
    assert!(
        matches!(
            park.wait.as_ref().map(|wait| &wait.wait),
            Some(DreamerParkWait::Budget { scope, .. }) if *scope == root
        ),
        "the scope step parks a budget wait on its root: got {:?}",
        park.wait
    );
    Ok(trap)
}

/// Host 1: two tries whose pass-bound steps found their guards spent park `PassBudget` waits. A
/// pass whose guard is still short wakes neither; a pass with room for one wakes the older only,
/// as the same try; a later pass with room wakes the other.
#[test]
fn a_pass_step_parks_on_its_pass_and_a_later_pass_with_room_wakes_it() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let backend = NeverBackend::new();

    let older = leased_try(&vault, "pass-budget-older", 20)?;
    let younger = leased_try(&vault, "pass-budget-younger", 21)?;
    let trap_older = park_on_pass(&vault, &older, 30_000, &backend)?;
    let trap_younger = park_on_pass(&vault, &younger, 31_000, &backend)?;
    assert_pass_budget_park(&store, &older, &trap_older)?;
    assert_pass_budget_park(&store, &younger, &trap_younger)?;
    assert!(
        store
            .parked_attempt(older.id)?
            .expect("older park")
            .parked_at
            < store
                .parked_attempt(younger.id)?
                .expect("younger park")
                .parked_at,
        "the older try parked first"
    );

    // A pass whose guard is one unit short of a reserve wakes nothing.
    run_pass(&vault, 1, STEP_RESERVE - 1, 40)?;
    for (row, trap) in [(&older, &trap_older), (&younger, &trap_younger)] {
        assert!(
            store.parked_attempt(row.id)?.is_some(),
            "a pass still short leaves the park standing"
        );
        assert_ne!(
            doors::trap_state(&vault, trap)?,
            llm::DreamerTrapState::Consumed,
            "a pass still short leaves the trap open"
        );
    }

    // A pass with room for one reserve, not two, wakes the older park only.
    run_pass(&vault, 2, STEP_RESERVE + STEP_RESERVE / 2, 50)?;
    assert_woken(&vault, &older, &trap_older, "a pass with room")?;
    assert!(
        store.parked_attempt(younger.id)?.is_some(),
        "the pass wakes no more than its room holds: the younger park stands"
    );

    // The next pass with room wakes the younger one.
    run_pass(&vault, 3, STEP_RESERVE * 4, 60)?;
    assert_woken(&vault, &younger, &trap_younger, "the next pass with room")?;
    assert_eq!(backend.calls(), 0, "no spent step called its backend");
    Ok(())
}

/// D2: the owner frees a park at its budget trap through `vault.runs.parks.release`. Resume wakes
/// a pass budget park and a scope budget park as the same tries; Stop ends a pass budget park's
/// try and a scope budget park's try, each trap consumed.
#[test]
fn the_owners_release_resumes_or_stops_a_try_parked_at_its_budget_trap() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let store = DreamerRunnerStore::new(&vault);
    let proof = embedded_owner_proof(&vault);
    let backend = NeverBackend::new();

    let pass_resumed = leased_try(&vault, "pass-budget-resume", 20)?;
    let pass_stopped = leased_try(&vault, "pass-budget-stop", 21)?;
    let scope_resumed = leased_try(&vault, "scope-budget-resume", 22)?;
    let scope_stopped = leased_try(&vault, "scope-budget-stop", 23)?;
    let trap_pass_resumed = park_on_pass(&vault, &pass_resumed, 30_000, &backend)?;
    let trap_pass_stopped = park_on_pass(&vault, &pass_stopped, 31_000, &backend)?;
    let trap_scope_resumed = park_on_scope(
        &vault,
        &scope_resumed,
        "pass-budget-wait-root-resume",
        32_000,
        &backend,
    )?;
    let trap_scope_stopped = park_on_scope(
        &vault,
        &scope_stopped,
        "pass-budget-wait-root-stop",
        33_000,
        &backend,
    )?;

    for (row, trap, what) in [
        (&pass_resumed, &trap_pass_resumed, "a pass budget park"),
        (&scope_resumed, &trap_scope_resumed, "a scope budget park"),
    ] {
        let park = store.parked_attempt(row.id)?.expect("the budget park");
        assert!(
            park.resumable_by(ParkResumer::OwnerRelease),
            "the owner's release may free {what}"
        );
        assert_eq!(
            release_doors::park_notice_seen(&vault, &park)?,
            None,
            "{what} has its own sender, so it raises no owner notice"
        );
        let released = release_doors::release_as_owner(
            &vault,
            &proof,
            &attempt_hex(row),
            DreamerParkCauseView::from(park.cause),
            park.parked_at,
            row.attempt_count,
        );
        let released = match released {
            Ok(released) => released,
            Err(error) => panic!("the owner's Resume serves {what}: got {error:?}"),
        };
        assert!(released.effected, "the owner's Resume of {what} queues it");
        assert_woken(&vault, row, trap, &format!("the owner's Resume of {what}"))?;
    }

    for (row, trap, what) in [
        (&pass_stopped, &trap_pass_stopped, "a pass budget park"),
        (&scope_stopped, &trap_scope_stopped, "a scope budget park"),
    ] {
        let park = store.parked_attempt(row.id)?.expect("the budget park");
        assert_eq!(
            park.cause,
            DreamerParkCause::Signal,
            "{what} waits on a signal"
        );
        let stopped = release_doors::stop_as_owner(
            &vault,
            &proof,
            &attempt_hex(row),
            DreamerParkCauseView::from(park.cause),
            park.parked_at,
            row.attempt_count,
        );
        let state = match stopped {
            Ok(state) => state,
            Err(error) => panic!("the owner's Stop serves {what}: got {error:?}"),
        };
        assert_eq!(
            state, "cancelled",
            "the owner's Stop of {what} ends the try"
        );
        assert!(
            store.parked_attempt(row.id)?.is_none(),
            "the owner's Stop of {what} clears the park"
        );
        assert_eq!(
            doors::trap_state(&vault, trap)?,
            llm::DreamerTrapState::Consumed,
            "the owner's Stop of {what} consumes its trap"
        );
    }
    assert_eq!(backend.calls(), 0, "no spent step called its backend");
    Ok(())
}

/// A step bound to neither a wake pass nor a spend scope, whose guard is spent, refuses `Unbound`
/// at once: no write refills its guard, so nothing parks and no trap opens.
#[test]
fn a_step_bound_to_no_pass_or_scope_refuses_unbound_and_parks_nothing() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let backend = NeverBackend::new();
    let row = leased_try(&vault, "unbound-step", 20)?;

    let refused = spent_step(&vault, &row, false, 30_000, &backend);
    let refusal = match refused {
        Err(llm::DurableStepError::BudgetRefused(refusal)) => refusal,
        other => panic!("an unbound spent step refuses typed, with no trap: got {other:?}"),
    };
    assert_eq!(
        refusal,
        StepBudgetRefusal::Unbound {
            asked_units: Some(STEP_RESERVE),
        },
        "the refusal names the reservation the spent guard refused"
    );
    assert!(
        DreamerRunnerStore::new(&vault)
            .parked_attempt(row.id)?
            .is_none(),
        "an unbound refusal parks nothing"
    );
    let after = AttemptQueue::new(&vault)
        .get(row.id)?
        .expect("the refused step's try");
    assert_eq!(
        after.state.as_str(),
        "leased",
        "the refused step's try keeps its lease for its host to end"
    );
    assert_eq!(after.attempt_count, row.attempt_count);
    assert_eq!(
        backend.calls(),
        0,
        "the refused step never called its backend"
    );
    Ok(())
}
