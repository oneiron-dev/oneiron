//! Row B1 of BUDGET-TRAP-UNTYPED-NO-SENDER: a step whose spend scope refuses its reservation for
//! good refuses at once with a typed reason, and no trap or park is left behind.
//!
//! A closed hard carve on the way to the open root that books the step has less room than the
//! reservation asks: nothing reopens it, so the step refuses `BoundaryClosed`, naming the carve.
//! A scope whose ceiling is below the reservation: a top-up does not raise a ceiling, so the step
//! refuses `CeilingReached`, naming the scope. Each step goes through the public `call_as_step`
//! with a paid request and a backend that must not be called, under the `guard_for_scope` guard of
//! its leased try's own scope. Scope fixtures come from `oneiron::test_doors::spend` and
//! `oneiron::test_doors::park_typed_wait`, built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId, SpendState};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DreamerConsolidationScope, DreamerRunnerStore,
    EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::store::model_step_submission::StepBudgetRefusal;
use oneiron::test_doors::park_typed_wait::reserve_child_hold_scope;
use oneiron::test_doors::spend::{reserve_child_scope, set_scope_ceiling};
use oneiron::{Vault, VaultConfig, WriteActor};

/// The lease owner the fixture's tries claim under.
const LEASE_OWNER: &str = "step-budget-refusal";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // A refused step answers without parking the thread, so polling again immediately is correct;
    // the bound catches a future pending on anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("refused step future pending on something other than an attempt-boundary yield");
}

/// A temporary vault with a process-memory device keystore, as the crate's test opener opens one.
fn open_vault() -> oneiron::Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Ok((dir, vault))
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

/// A backend a refused step must never reach: any call panics, and the count stays readable.
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
        panic!("a refused step must not call its backend");
    }

    fn stream<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmStreamResult<'a> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        panic!("a refused step must not call its backend");
    }
}

/// One leased try: a micro consolidation attempt enqueued under `tag` and claimed under the
/// fixture's lease owner, so a step that wrongly parks would park under a live lease.
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

/// The default guard reserve: what a step's reservation asks of its scope.
fn default_reserve() -> u64 {
    llm::BudgetGuard::new(
        "step-budget-refusal-reserve",
        0,
        llm::BudgetExhaustionPolicy::Suspend,
    )
    .reserve_units()
}

/// Opens a hard root of `units`, shown at its start.
fn open_root(
    dispatcher: &AgentDispatcher<'_>,
    name: &str,
    units: u64,
) -> Result<SpendScopeId, Box<dyn std::error::Error>> {
    let root = SpendScopeId::launch(name)?;
    let opened = dispatcher
        .open_root_spend_scope(
            root.clone(),
            DeclaredMaximum {
                units,
                unit: LeaseUnit::tokens(),
            },
            Some(MaximumShown { at_ms: 12_000 }),
            12,
        )
        .expect("the hard root opens");
    assert!(opened.hard, "the root is a hard cap");
    assert_eq!(opened.state, SpendState::Open, "the root opens open");
    Ok(root)
}

/// Runs one paid step of `row`'s try under `scope`'s guard, bound to `scope`.
fn step_under(
    vault: &Vault,
    row: &AttemptRecord,
    scope: &SpendScopeId,
    backend: &NeverBackend,
) -> Result<llm::DurableStepResult<llm::StepOutcome>, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let spend = llm::StepSpendScope::read_before_guards(vault, scope.clone())?;
    let guard = AgentDispatcher::new(vault).guard_for_scope(scope)?;
    let ctx = llm::DurableStepContext {
        vault,
        attempt_id: row.id,
        run_id: None,
        envelope_actor: WriteActor::new(owner, EdgeActorClass::Human),
        subject: owner,
        deadline: None,
        now_ms: 43_000,
        spend_scope: Some(spend),
        wake_pass_bound: false,
    };
    Ok(block_on_ready(llm::call_as_step(
        &ctx,
        backend,
        &guard,
        paid_step_request("step budget refusal"),
    )))
}

/// What a refused step must leave: its try still leased under its own lease, unparked, and its
/// backend never called.
fn assert_nothing_parked(
    vault: &Vault,
    row: &AttemptRecord,
    backend: &NeverBackend,
) -> Result<(), Box<dyn std::error::Error>> {
    assert!(
        DreamerRunnerStore::new(vault)
            .parked_attempt(row.id)?
            .is_none(),
        "a refused step parks nothing"
    );
    let after = AttemptQueue::new(vault)
        .get(row.id)?
        .expect("the refused step's try");
    assert_eq!(
        after.state.as_str(),
        "leased",
        "a refused step leaves its try leased, for its host to end"
    );
    assert_eq!(
        after.lease_owner.as_deref(),
        Some(LEASE_OWNER),
        "a refused step leaves its try's lease as it was"
    );
    assert_eq!(backend.calls(), 0, "a refused step never calls its backend");
    Ok(())
}

/// Host 4 (closed boundary): the step's soft scope sits under a hard carve that settled and
/// closed, with less room than the reservation asks of it. The open root above has room for the
/// whole reservation, but nothing reopens the carve, so the step refuses `BoundaryClosed` naming
/// the carve, and no trap or park is left.
#[test]
fn a_step_whose_reservation_passes_a_closed_carve_refuses_typed_and_parks_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let reserve = default_reserve();
    let carve_cap = reserve / 2;
    let hold = 10;
    assert!(
        (hold + 1..reserve).contains(&carve_cap),
        "the carve holds the try's hold and less than the reservation"
    );
    let root = open_root(&dispatcher, "owen-carve-root", 4 * reserve)?;

    let carve_try = AttemptId::now();
    let carve = reserve_child_scope(&vault, &root, &carve_try, carve_cap, 13)?;
    assert!(carve.hard, "the carve is a hard cap");
    let row = leased_try(&vault, "step-budget-refusal-carve", 14)?;
    let child = reserve_child_hold_scope(&vault, &carve.scope, &row.id, hold, 15)?;
    assert!(!child.hard, "the try's own scope is a soft hold");
    assert_eq!(
        child.parent.as_ref(),
        Some(&carve.scope),
        "the try's scope sits under the carve"
    );
    assert_eq!(child.cap_units, hold, "the try holds its hold");
    dispatcher
        .settle_child(&carve_try, 16)?
        .expect("the carve settles");
    let closed = dispatcher
        .read_spend_scope(&carve.scope)?
        .expect("the closed carve");
    assert_eq!(closed.state, SpendState::Closed, "the carve is closed");
    let child = dispatcher
        .read_spend_scope(&child.scope)?
        .expect("the try's scope");
    assert_eq!(
        child.state,
        SpendState::Open,
        "the try's scope stays open under the closed carve"
    );
    let room = carve_cap - hold;
    assert_eq!(
        dispatcher.available_units(&child.scope)?,
        hold + room,
        "the try may spend its hold and the closed carve's room, no more"
    );

    let backend = NeverBackend::new();
    let refused = step_under(&vault, &row, &child.scope, &backend)?;
    let refusal = match refused {
        Err(llm::DurableStepError::BudgetRefused(refusal)) => refusal,
        other => panic!("the closed carve refuses the step typed, with no trap: got {other:?}"),
    };
    assert_eq!(
        refusal,
        StepBudgetRefusal::BoundaryClosed {
            scope: carve.scope.as_str().to_owned(),
            available_units: room,
            asked_units: reserve - hold,
        },
        "the refusal names the closed carve, its room and what the reservation asked of it"
    );
    assert_nothing_parked(&vault, &row, &backend)
}

/// Host 3d (ceiling): the step's scope is a hard carve with room under its cap for the whole
/// reservation, whose ceiling, set at launch, is below it. A top-up of its cap does not raise the
/// ceiling, so the step refuses `CeilingReached` naming the carve, and no trap or park is left.
#[test]
fn a_step_at_its_scopes_ceiling_refuses_typed_and_parks_nothing()
-> Result<(), Box<dyn std::error::Error>> {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let reserve = default_reserve();
    let ceiling = reserve / 2;
    assert!(
        (1..reserve).contains(&ceiling),
        "the ceiling is below the reservation"
    );
    let root = open_root(&dispatcher, "yuki-ceiling-root", 4 * reserve)?;

    let row = leased_try(&vault, "step-budget-refusal-ceiling", 14)?;
    let carve = reserve_child_scope(&vault, &root, &row.id, 2 * reserve, 15)?;
    assert!(carve.hard, "the try's own scope is a hard carve");
    assert!(
        carve.local_available() >= reserve,
        "the carve's cap has room for the whole reservation"
    );
    let capped = set_scope_ceiling(&vault, &carve.scope, ceiling)?;
    assert_eq!(
        capped.ceiling_units,
        Some(ceiling),
        "the carve's ceiling is set"
    );
    assert_eq!(
        dispatcher.available_units(&carve.scope)?,
        ceiling,
        "the try may spend up to its ceiling, no more"
    );

    let backend = NeverBackend::new();
    let refused = step_under(&vault, &row, &carve.scope, &backend)?;
    let refusal = match refused {
        Err(llm::DurableStepError::BudgetRefused(refusal)) => refusal,
        other => panic!("the ceiling refuses the step typed, with no trap: got {other:?}"),
    };
    assert_eq!(
        refusal,
        StepBudgetRefusal::CeilingReached {
            scope: carve.scope.as_str().to_owned(),
            available_units: ceiling,
            asked_units: reserve,
        },
        "the refusal names the carve, the room under its ceiling and the whole reservation"
    );
    assert_nothing_parked(&vault, &row, &backend)
}
