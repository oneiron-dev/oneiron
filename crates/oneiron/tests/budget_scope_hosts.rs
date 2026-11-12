//! Row B3 of BUDGET-TRAP-UNTYPED-NO-SENDER: the hosts whose steps spend under a spend scope.
//!
//! - A free-time item's step spends under its item's scope, inside its wake pass. A scope that
//!   refuses the step for good (here a ceiling on the item's pinned carve) ends the try `Failed`,
//!   typed on its row and on its item's receipt; nothing parks and the backend is never called.
//! - A free-time item's spent pass step parks a `PassBudget` wait that names its scope's nearest
//!   open hard scope (the cycle root, for an item with no pinned share). Besides the next pass, a
//!   top-up of that root wakes the park in the top-up's own write.
//! - A run's media step spends under the run's scope. A spent media call parks a `Budget` wait on
//!   the hard scope that refused it, asking the run line's reserve, and that scope's top-up wakes
//!   it; a ceiling refuses it typed.
//!
//! The free-time items run through a real Timer pass of the `DreamerWakeDriver` and the public
//! `run_free_time_for_human`, with a host that lends a spent step guard and a backend that must not
//! be called. Doors come from `oneiron::test_doors`, built only under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test budget_scope_hosts`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{AgentDispatcher, SpendScopeId};
use oneiron::attempt_queue::{AttemptId, AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_consolidation::{ResidentDreamModel, run_free_time_for_human};
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND,
    DREAMER_SERVER_PARK_OWNER, DreamerConsolidationScope, DreamerParkWait, DreamerParkedWait,
    DreamerRunnerStore, EnqueueDreamerAttemptOutcome, EnqueueDreamerConsolidationAttempt,
    FreeTimeCadence, FreeTimeItemBinding, FreeTimeItemOutcome, FreeTimeKind, FreeTimePolicyInput,
    FreeTimeSchedule, FreeTimeSplit, ParkResumer,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::llm::media::{AiOperation, MediaPart, MediaRequest, MediaResponse};
use oneiron::llm::run_admission::{DeclaredMaximum, LeaseUnit, MaximumShown};
use oneiron::llm::{HostInferenceBinding, HostInferenceContext};
use oneiron::store::model_step_submission::StepBudgetRefusal;
use oneiron::test_doors::coach::define_agent;
use oneiron::test_doors::park_typed_wait as doors;
use oneiron::test_doors::spend::{reserve_child_scope, set_scope_ceiling};
use oneiron::test_doors::steward::{open_owner_carrier_vault, owner};
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{
    CallPurpose, DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerAttemptExecutor,
    DreamerWakeDriver, EntityId, ModelLocality, RunWakePass, Vault, VaultConfig,
    WakeAttemptContext, WakeCancellation, WakePassDeadline, WakePassReport, WakeTrigger,
    WriteActor,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The reserve every spent step guard here asks: the units a refused reservation asks.
const STEP_RESERVE: u64 = 500;
/// The free-time policy's total: the cycle root's cap.
const FREE_TIME_TOTAL: u64 = 10_000;
/// A pass time well past the policy's first boundary, never the wall.
const PASS_NOW: u64 = 4_000_000_000;

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
    panic!("a budget scope future pending on something other than an attempt-boundary yield");
}

/// A backend a spent or refused step must never reach: any call panics, and the count stays
/// readable.
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

/// The host egress an own-server call runs under: every fixture call permitted.
fn allow_egress(_: &llm::LlmRequest) -> bool {
    true
}

/// A frozen pass deadline, as the WAKE-D1 fixture builds one.
fn frozen_deadline() -> WakePassDeadline {
    let elapsed = Arc::new(AtomicU64::new(0));
    WakePassDeadline::with_clock(180_000, Arc::new(move || elapsed.load(Ordering::SeqCst)))
}

/// Widens the vault's inference defaults so an own-server call of a free-time item is admitted:
/// its call is gated as an extraction.
fn widen_inference(vault: &Vault) {
    let mut table = vault.purpose_default_table().expect("default table");
    table.extraction_max_locality = ModelLocality::OwnServer;
    for purpose in [CallPurpose::Extraction, CallPurpose::AutonomyForHuman] {
        if let Some(row) = table.purposes.get_mut(&purpose) {
            row.locality = ModelLocality::OwnServer;
        }
    }
    vault
        .set_purpose_default_table(&table)
        .expect("widened table");
}

/// One resident with a free-time policy on an owner-carrier vault, its vault's node the elected
/// home of its cycles.
struct FreeTime {
    _dir: tempfile::TempDir,
    vault: Vault,
    owner: AuthenticatedOwner,
    agent: EntityId,
    node: u64,
}

/// One open cycle's item for the resident's human: its cycle, its try, and its binding.
struct ForHumanItem {
    cycle: EntityId,
    root: SpendScopeId,
    attempt: AttemptId,
    binding: FreeTimeItemBinding,
}

impl FreeTime {
    fn open(pinned_split: Option<FreeTimeSplit>) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let vault = open_owner_carrier_vault(dir.path())?;
        let owner = owner(&vault)?;
        let agent = define_agent(&vault)?;
        widen_inference(&vault);
        let _policy = vault.set_free_time_policy(
            &owner,
            None,
            agent,
            0,
            FreeTimePolicyInput {
                total_units: FREE_TIME_TOTAL,
                schedule: FreeTimeSchedule {
                    cadence: FreeTimeCadence::Nightly,
                    hour: 2,
                    minute: 0,
                    zone: "Asia/Tokyo".to_owned(),
                },
                pinned_split,
                cap_shown_at_ms: 1_000,
            },
        )?;
        let node = release_doors::load_or_mint_client_id(&vault)?;
        let store = DreamerRunnerStore::new(&vault);
        let candidate = store.local_home_node_candidate(true, true, true)?;
        let home = store
            .elect_home_node(&[candidate], PASS_NOW)?
            .expect("the vault's node is elected home");
        assert_eq!(home.node_id, node, "the vault's own node is its home");
        Ok(Self {
            _dir: dir,
            vault,
            owner,
            agent,
            node,
        })
    }

    /// Opens the policy's first cycle at the pass time and returns its item for the resident's
    /// human, its try queued and its scope reserved under the cycle's root.
    fn open_cycle(&self) -> Result<ForHumanItem, Box<dyn std::error::Error>> {
        let opened = self
            .vault
            .enqueue_due_free_time_cycles(PASS_NOW, self.node)?;
        assert_eq!(opened, 1, "the policy's first boundary opens one cycle");
        let sheets = self.vault.free_time_cycles(self.agent, None, 1)?;
        let sheet = sheets.first().expect("the open cycle's sheet");
        let item = sheet
            .cycle
            .items
            .iter()
            .find(|item| item.kind == FreeTimeKind::ForHuman)
            .expect("the cycle's item for the resident's human");
        let attempt = AttemptId::from_bytes(&item.attempt.expect("the item's try"))?;
        let binding = self
            .vault
            .free_time_item_binding(attempt)?
            .expect("the item's binding");
        Ok(ForHumanItem {
            cycle: sheet.cycle.cycle,
            root: sheet.cycle.root_scope.clone(),
            attempt,
            binding,
        })
    }

    /// Runs one Timer pass of the server's Dreamer on the home node, at the pass time.
    fn run_timer_pass(
        &self,
        host: &mut ItemHost<'_>,
    ) -> Result<WakePassReport, Box<dyn std::error::Error>> {
        let guard = llm::BudgetGuard::with_reserve_units(
            "budget-scope-hosts:p1",
            FREE_TIME_TOTAL,
            100,
            llm::BudgetExhaustionPolicy::Suspend,
        );
        let mut driver =
            DreamerWakeDriver::new(&self.vault, "wake", frozen_deadline()).with_budget_guard(guard);
        Ok(block_on_ready(driver.run_wake_pass(
            RunWakePass {
                trigger: WakeTrigger::Timer,
                scope: DreamerConsolidationScope::Macro,
                local_node_id: self.node,
                lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
                budget_total_units: FREE_TIME_TOTAL,
                reserve_units: 100,
                now: PASS_NOW,
                host_scope: None,
                destination_bound: None,
            },
            host,
            &WakeCancellation::new(),
        ))?)
    }
}

/// The host of a free-time item, as the server's free-time host lends its model: it reads the
/// item's scope before it builds the step's guard, and lends a step guard that is spent, so the
/// item's one step meets its budget. Every other try the pass admits ends without work.
struct ItemHost<'b> {
    backend: &'b NeverBackend,
    ran: usize,
}

impl<'b> ItemHost<'b> {
    fn new(backend: &'b NeverBackend) -> Self {
        Self { backend, ran: 0 }
    }
}

impl DreamerAttemptExecutor for ItemHost<'_> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> oneiron::Result<DreamerAttemptExecution> {
        if attempt.status.payload.attempt_type != DREAMER_FREE_TIME_FOR_HUMAN_ATTEMPT_KIND {
            return Ok(DreamerAttemptExecution::Completed {
                completed_units: 0,
                step_bindings: Vec::new(),
            });
        }
        self.ran += 1;
        let binding = ctx
            .vault
            .free_time_item_binding(attempt.status.attempt.id)?
            .expect("the admitted item's binding");
        let spend_scope = llm::StepSpendScope::read_before_guards(ctx.vault, binding.spend_scope)?;
        let guard = llm::BudgetGuard::with_reserve_units(
            "budget-scope-hosts:item-step",
            0,
            STEP_RESERVE,
            llm::BudgetExhaustionPolicy::Suspend,
        );
        let model = llm::ModelId::new("test/model@r1").expect("model id");
        let lent = ResidentDreamModel {
            backend: self.backend,
            guard: &guard,
            model: model.clone(),
            inference: HostInferenceContext {
                binding: HostInferenceBinding::Advertised {
                    model,
                    locality: ModelLocality::OwnServer,
                    keyless: false,
                },
                extraction_egress: Some(&allow_egress),
            },
            role: None,
            instruction: "Suggest one small thing for your human.",
            window_tokens: None,
            sourced: None,
            spend_scope: Some(spend_scope),
        };
        run_free_time_for_human(attempt, ctx, lent).await
    }
}

/// A free-time item whose pinned carve sits at its ceiling, below the step's reserve, runs in a
/// Timer pass: its step refuses `CeilingReached` and the try ends `Failed`, typed on its row and on
/// its item's receipt. Nothing parks, and the backend is never called.
#[test]
fn a_free_time_item_its_carves_ceiling_refuses_ends_failed_typed_on_its_row_and_receipt()
-> TestResult {
    let fixture = FreeTime::open(Some(FreeTimeSplit {
        for_human_units: 4 * STEP_RESERVE,
        own_time_units: 4 * STEP_RESERVE,
    }))?;
    let item = fixture.open_cycle()?;
    let dispatcher = AgentDispatcher::new(&fixture.vault);
    let carve = dispatcher
        .read_spend_scope(&item.binding.spend_scope)?
        .expect("the item's scope");
    assert!(carve.hard, "a pinned share is a hard carve");
    let ceiling = STEP_RESERVE / 5;
    set_scope_ceiling(&fixture.vault, &item.binding.spend_scope, ceiling)?;
    assert_eq!(
        dispatcher.available_units(&item.binding.spend_scope)?,
        ceiling,
        "the item may spend up to its carve's ceiling, no more"
    );

    let backend = NeverBackend::new();
    let mut host = ItemHost::new(&backend);
    let report = fixture.run_timer_pass(&mut host)?;
    assert_eq!(host.ran, 1, "the pass runs the item once: {report:?}");

    let refusal = StepBudgetRefusal::CeilingReached {
        scope: item.binding.spend_scope.as_str().to_owned(),
        available_units: ceiling,
        asked_units: STEP_RESERVE,
    };
    let row = AttemptQueue::new(&fixture.vault)
        .get(item.attempt)?
        .expect("the item's try");
    assert_eq!(
        row.state.as_str(),
        "failed",
        "the refused item's try ends failed: {report:?}"
    );
    assert_eq!(
        row.budget_refusal,
        Some(refusal.clone()),
        "the failed row keeps the typed refusal beside its text"
    );
    assert!(row.last_error.is_some(), "the failed row says why");
    assert!(
        DreamerRunnerStore::new(&fixture.vault)
            .parked_attempt(item.attempt)?
            .is_none(),
        "a refused item parks nothing"
    );
    let sheet = fixture
        .vault
        .free_time_cycle(fixture.agent, item.cycle)?
        .expect("the cycle's sheet");
    let receipt = sheet
        .receipts
        .iter()
        .find(|receipt| receipt.kind == FreeTimeKind::ForHuman)
        .expect("the item's receipt");
    assert_eq!(
        receipt.outcome,
        FreeTimeItemOutcome::Failed,
        "the item's receipt says it failed"
    );
    assert_eq!(
        receipt.budget_refusal,
        Some(refusal),
        "the item's receipt carries the typed refusal"
    );
    assert_eq!(backend.calls(), 0, "a refused step never calls its backend");
    Ok(())
}

/// A free-time item with no pinned share holds a soft scope under its cycle's hard root. Its step
/// finds the step guard spent while the root still has room, so it parks a `PassBudget` wait that
/// names the root, at its trap. The root's top-up wakes it in the top-up's own write, as the same
/// try.
#[test]
fn a_free_time_items_spent_pass_step_parks_on_its_pass_and_its_roots_top_up_wakes_it() -> TestResult
{
    let fixture = FreeTime::open(None)?;
    let item = fixture.open_cycle()?;
    let store = DreamerRunnerStore::new(&fixture.vault);

    let backend = NeverBackend::new();
    let mut host = ItemHost::new(&backend);
    let report = fixture.run_timer_pass(&mut host)?;
    assert_eq!(host.ran, 1, "the pass runs the item once: {report:?}");

    let row = AttemptQueue::new(&fixture.vault)
        .get(item.attempt)?
        .expect("the item's try");
    let park = store
        .parked_attempt(item.attempt)?
        .unwrap_or_else(|| panic!("the item's spent step parks its try: {report:?} {row:?}"));
    assert_eq!(
        park.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::PassBudget {
                asked_units: STEP_RESERVE,
                scope: Some(item.root.clone()),
            },
            lease_generation: row.attempt_count,
        }),
        "the item's spent pass step waits on its pass and names its cycle's root"
    );
    assert!(
        park.resumable_by(ParkResumer::PassStart),
        "a later pass with room may wake the item"
    );
    assert!(
        park.resumable_by(ParkResumer::BudgetTopUp),
        "a top-up of the root may wake the item"
    );
    assert!(
        !park.resumable_by(ParkResumer::LaterPass),
        "no blind later pass resumes the item"
    );

    let raised = AgentDispatcher::new(&fixture.vault).top_up_spend_scope_as_owner(
        &fixture.owner,
        &item.root,
        FREE_TIME_TOTAL,
        DeclaredMaximum {
            units: 2 * FREE_TIME_TOTAL,
            unit: LeaseUnit::tokens(),
        },
        MaximumShown { at_ms: 2_000 },
    )?;
    assert_eq!(raised.cap_units, 2 * FREE_TIME_TOTAL, "the root's cap rose");
    assert!(
        store.parked_attempt(item.attempt)?.is_none(),
        "the root's top-up wakes the item's park in its own write"
    );
    let status = store.status(item.attempt)?.expect("the woken item's row");
    assert_eq!(
        status.attempt.state.as_str(),
        "queued",
        "the top-up queues the same try again"
    );
    assert_eq!(
        status.attempt.attempt_count, row.attempt_count,
        "the top-up keeps the try's lease generation"
    );
    assert_eq!(backend.calls(), 0, "a spent step never calls its backend");
    Ok(())
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
fn embedded_owner_proof(vault: &Vault) -> AuthenticatedOwner {
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

/// One micro consolidation try enqueued under `tag` and claimed under the Dreamer server's lease
/// owner, so its step parks under a live lease, as a run's leased try does.
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

/// One image call of `row`'s run as its durable media step under `scope`, whose run line reserves
/// the step reserve per call. The media path answers that its line is spent before any rung
/// admitted it.
fn spent_media_step(
    vault: &Vault,
    row: &AttemptRecord,
    scope: &SpendScopeId,
    now_ms: u64,
) -> Result<llm::DurableStepResult<llm::MediaStepOutcome>, Box<dyn std::error::Error>> {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let ctx = llm::DurableStepContext {
        vault,
        attempt_id: row.id,
        run_id: None,
        envelope_actor: WriteActor::new(owner, EdgeActorClass::Human),
        subject: owner,
        deadline: None,
        now_ms,
        spend_scope: Some(llm::StepSpendScope::read_before_guards(
            vault,
            scope.clone(),
        )?),
        wake_pass_bound: false,
    };
    let request = MediaRequest {
        model: llm::ModelId::new("test/image@r1").expect("model id"),
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
        operation: AiOperation::Image,
        parts: vec![MediaPart::Text {
            text: "a lighthouse at dusk".to_owned(),
        }],
        references: Vec::new(),
        mask: None,
        params: Default::default(),
        voice: None,
    };
    let admitted = AtomicBool::new(false);
    Ok(block_on_ready(llm::call_media_as_step(
        &ctx,
        request,
        Some(STEP_RESERVE),
        &admitted,
        |_request| {
            std::future::ready(Err::<MediaResponse, llm::LlmError>(
                llm::LlmError::BudgetDenied(llm::BudgetDenied::Exhausted),
            ))
        },
    )))
}

/// A run's media step bound to a hard root whose cap sits below the run line's reserve parks a
/// `Budget` wait on that root, asking the reserve. The root's top-up wakes it in its own write, as
/// the same try.
#[test]
fn a_media_step_bound_to_a_hard_root_parks_on_the_root_and_its_top_up_wakes_it() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let store = DreamerRunnerStore::new(&vault);
    let root_cap = STEP_RESERVE / 5;
    let root = open_root(&dispatcher, "owen-media-root", root_cap)?;
    let row = leased_try(&vault, "budget-scope-media-root", 20)?;

    let outcome = spent_media_step(&vault, &row, &root, 30_000)?;
    let trap = match outcome {
        Ok(llm::MediaStepOutcome::Trapped { trap, .. }) => trap,
        other => panic!("a media step its root refuses parks at its trap: got {other:?}"),
    };
    let park = store
        .parked_attempt(row.id)?
        .expect("the media step's park");
    assert_eq!(
        park.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Budget {
                scope: root.clone(),
                asked_units: STEP_RESERVE,
            },
            lease_generation: row.attempt_count,
        }),
        "the media step waits on its root, asking the run line's reserve"
    );

    let raised = dispatcher.top_up_spend_scope_as_owner(
        &embedded_owner_proof(&vault),
        &root,
        root_cap,
        DeclaredMaximum {
            units: 4 * STEP_RESERVE,
            unit: LeaseUnit::tokens(),
        },
        MaximumShown { at_ms: 31_000 },
    )?;
    assert_eq!(raised.cap_units, 4 * STEP_RESERVE, "the root's cap rose");
    assert!(
        store.parked_attempt(row.id)?.is_none(),
        "the root's top-up wakes the media step's park"
    );
    assert_eq!(
        doors::trap_state(&vault, &trap)?,
        llm::DreamerTrapState::Consumed,
        "the top-up consumes the media step's trap"
    );
    let status = store.status(row.id)?.expect("the woken try's row");
    assert_eq!(
        status.attempt.state.as_str(),
        "queued",
        "the top-up queues the same try again"
    );
    assert_eq!(
        status.attempt.attempt_count, row.attempt_count,
        "the top-up keeps the try's lease generation"
    );
    Ok(())
}

/// A run's media step bound to a carve whose ceiling sits below the run line's reserve refuses
/// `CeilingReached`, typed, and parks nothing: no top-up lifts a ceiling.
#[test]
fn a_media_step_at_its_scopes_ceiling_refuses_typed_and_parks_nothing() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let dispatcher = AgentDispatcher::new(&vault);
    let root = open_root(&dispatcher, "yuki-media-ceiling-root", 4 * STEP_RESERVE)?;
    let row = leased_try(&vault, "budget-scope-media-ceiling", 20)?;
    let carve = reserve_child_scope(&vault, &root, &row.id, 2 * STEP_RESERVE, 21)?;
    let ceiling = STEP_RESERVE / 2;
    set_scope_ceiling(&vault, &carve.scope, ceiling)?;

    let outcome = spent_media_step(&vault, &row, &carve.scope, 30_000)?;
    let refusal = match outcome {
        Err(llm::DurableStepError::BudgetRefused(refusal)) => refusal,
        other => panic!("the ceiling refuses the media step typed, with no trap: got {other:?}"),
    };
    assert_eq!(
        refusal,
        StepBudgetRefusal::CeilingReached {
            scope: carve.scope.as_str().to_owned(),
            available_units: ceiling,
            asked_units: STEP_RESERVE,
        },
        "the refusal names the carve, the room under its ceiling and the run line's reserve"
    );
    assert!(
        DreamerRunnerStore::new(&vault)
            .parked_attempt(row.id)?
            .is_none(),
        "a refused media step parks nothing"
    );
    Ok(())
}
