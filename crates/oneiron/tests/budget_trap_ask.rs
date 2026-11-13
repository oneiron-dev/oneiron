//! A Dreamer try parked at its budget trap on a wait only an owner act ends
//! asks its owner (ARCH-0026 depletion ladder; Engine ruling RUNBUDGET-SCOPE =
//! B, 13 Nov 17:30), through the run-budget family on its own queue:
//! - a park on a resident's spent pinned share, or on the hard cap of a spend
//!   scope the owner may raise, queues one owner ask in the park's own write,
//!   keyed by the try; with no answer, and on `stay_parked`, the try stays
//!   parked;
//! - the owner's `overdraft` raises the limit that stopped the try by the cap
//!   he names (one more call by default) and wakes the park in the answer's
//!   write;
//! - a park on its wake pass's guard asks nothing: a later pass with room
//!   wakes it;
//! - any wake of the park (the owner's release, his share write) withdraws
//!   the open ask.
//!
//! Each step goes through the public `call_as_step`. The tests read only
//! doors the base already has (the decision ask list, the owner's answer and
//! press, the share write, the owner's release), so they run red on the
//! base. Trap states and the owner's release go through
//! `oneiron::test_doors`, built only under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron
//! --all-features --test budget_trap_ask`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use oneiron::agent_dispatch::{AgentDispatcher, RunBudgetChoice, SpendScopeId};
use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::consent::AuthenticatedOwner;
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DREAMER_SERVER_PARK_OWNER, DreamerConsolidationScope,
    DreamerParkWait, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::llm::decision::{AnswerContract, DecisionAnswer, DecisionAsk};
use oneiron::llm::run_admission::resident_doors::{
    SetResidentShareRequest, set_resident_share_as_owner,
};
use oneiron::llm::run_admission::{
    Allocation, AllocationRef, BudgetLine, DeclaredMaximum, HostAccount, KeyCustody, LeaseUnit,
    MaximumShown, MemoryReceipts, OfferBinding, OfferRoute, Payer, RunAdmission, RunCall,
    RunDeclaration,
};
use oneiron::memory::DreamerParkCauseView;
use oneiron::test_doors::park_typed_wait as doors;
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{EntityId, Vault, VaultConfig, WriteActor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The queue identity of budget trap asks.
const BUDGET_TRAP_QUEUE: &str = "models.budget_trap_questions";
/// The model every request and offer here names.
const MODEL: &str = "test/model@r1";
/// What each host-paid call reserves, in tokens.
const STEP_RESERVE: u64 = 500;
/// Room enough for every call here on the step's guard and the run's line.
const ROOM_UNITS: u64 = 10_000;
/// The host's allocation, in tokens: far more than any call here asks.
const ALLOCATION_UNITS: u64 = 100_000;
/// A root scope's cap, well below any scope guard's reserve.
const SCOPE_CAP: u64 = 100;

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // The backend answers at once and a refused or parked step never awaits anything else, so
    // polling again immediately is correct; the bound catches a future pending on anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("a step pending on something other than its backend's answer");
}

/// A temporary vault with a process-memory device keystore and its embedded owner.
fn open_vault() -> oneiron::Result<(tempfile::TempDir, Vault)> {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault = Vault::open(dir.path(), VaultConfig::device())?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault.ensure_embedded_owner_actor().expect("embedded owner");
    Ok((dir, vault))
}

/// The vault's embedded owner, authenticated: what an owner door takes.
fn owner_proof(vault: &Vault) -> AuthenticatedOwner {
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

/// One paid model request on the owner's own server.
fn paid_step_request(text: &str) -> llm::LlmRequest {
    llm::LlmRequest {
        model: llm::ModelId::new(MODEL).expect("model id"),
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

/// The host's paid offer of the model on the owner's own server, under a T0 key, priced in tokens.
fn host_offer() -> OfferBinding {
    OfferBinding {
        offer: format!("{MODEL}@model.test"),
        model: llm::ModelId::new(MODEL).expect("model id"),
        route: OfferRoute::new("fake", "https://model.test:443").expect("route"),
        locality: llm::ModelLocality::OwnServer,
        payer: Payer::Host,
        credential_binding: Some("host-key-1".to_owned()),
        catalog_revision: Some("catalog-7".to_owned()),
        custody: KeyCustody::T0,
        rates: Vec::new(),
        payer_person: None,
    }
}

/// A host-paid model backend: it runs the host's run admission for each call and answers a
/// refusal as the model error the refusal reads as. It sends nothing: an admitted call answers a
/// fatal error, which no step here reaches.
struct AdmittingBackend {
    run: RunAdmission,
    offer: OfferBinding,
}

impl AdmittingBackend {
    /// A backend over `resident`'s declared run, paid by `host`.
    fn new(resident: EntityId, host: Option<Arc<HostAccount>>) -> Self {
        let run = RunAdmission::new(
            "budget-trap-ask",
            RunDeclaration::declared(BudgetLine {
                limit_units: ROOM_UNITS,
                reserve_units: STEP_RESERVE,
                unit: LeaseUnit::tokens(),
            }),
            host,
            Arc::new(MemoryReceipts::default()),
        )
        .initiated_by(Some(resident));
        Self {
            run,
            offer: host_offer(),
        }
    }

    /// Whether the run admission admits one more call of the step's request now.
    fn admits(&self) -> bool {
        let request = paid_step_request("budget trap step");
        self.run
            .admit(RunCall {
                selector: None,
                request: &request,
                offer: &self.offer,
            })
            .is_ok()
    }
}

impl llm::LlmBackend for AdmittingBackend {
    fn generate<'a>(
        &'a self,
        request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmGenerateFuture<'a> {
        let answer = match self.run.admit(RunCall {
            selector: None,
            request: &request,
            offer: &self.offer,
        }) {
            Ok(_permit) => Err(llm::LlmError::Fatal(llm::FatalLlmError::EmptyResponse)),
            Err(denied) => Err(llm::LlmError::from(denied)),
        };
        Box::pin(std::future::ready(answer))
    }

    fn stream<'a>(
        &'a self,
        _request: llm::LlmRequest,
        _lease: &'a llm::BudgetLease,
    ) -> llm::LlmStreamResult<'a> {
        panic!("a durable step's paid call here generates; it never streams");
    }
}

/// A host account over the vault's resident ledger, with an allocation far above any call here.
fn host_account(vault: &Arc<Vault>) -> oneiron::Result<Arc<HostAccount>> {
    let account = HostAccount::with_residents(llm::VaultResidentLedger::new(Arc::clone(vault)));
    account.grant(Allocation {
        reference: AllocationRef {
            id: "allocation-1".to_owned(),
            generation: 1,
        },
        units: ALLOCATION_UNITS,
        unit: LeaseUnit::tokens(),
        wallet: None,
    })?;
    Ok(account)
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

/// Runs one step of `row`'s try under `guard`, with `spend_scope` and bound to its wake pass when
/// `wake_pass_bound`, and returns its trap: every step here traps.
fn trapped_step(
    vault: &Vault,
    row: &AttemptRecord,
    backend: &AdmittingBackend,
    guard: &llm::BudgetGuard,
    spend_scope: Option<llm::StepSpendScope>,
    wake_pass_bound: bool,
) -> llm::TrapRef {
    let owner = vault.ensure_embedded_owner_actor().expect("embedded owner");
    let ctx = llm::DurableStepContext {
        vault,
        attempt_id: row.id,
        run_id: None,
        envelope_actor: WriteActor::new(owner, EdgeActorClass::Human),
        subject: owner,
        deadline: None,
        now_ms: 1_000,
        spend_scope,
        wake_pass_bound,
    };
    let outcome = block_on_ready(llm::call_as_step(
        &ctx,
        backend,
        guard,
        paid_step_request("budget trap step"),
    ));
    match outcome {
        Ok(llm::StepOutcome::Trapped { trap, .. }) => {
            assert_eq!(
                trap.kind,
                llm::DreamerTrapKind::Budget,
                "the step parks at a budget trap"
            );
            trap
        }
        other => panic!("the spent budget traps the step: got {other:?}"),
    }
}

/// A step guard with room for every call here: only the run admission below it refuses.
fn roomy_guard() -> llm::BudgetGuard {
    llm::BudgetGuard::with_reserve_units(
        "budget-trap-ask",
        ROOM_UNITS,
        STEP_RESERVE,
        llm::BudgetExhaustionPolicy::Suspend,
    )
}

/// Parks `row`'s try on `resident`'s spent pinned share and asserts its wait.
fn park_on_share(
    vault: &Vault,
    row: &AttemptRecord,
    resident: EntityId,
    backend: &AdmittingBackend,
) -> Result<llm::TrapRef, Box<dyn std::error::Error>> {
    let trap = trapped_step(vault, row, backend, &roomy_guard(), None, true);
    let park = DreamerRunnerStore::new(vault)
        .parked_attempt(row.id)?
        .expect("the resident's step park");
    assert_eq!(
        park.wait.map(|wait| wait.wait),
        Some(DreamerParkWait::ResidentShare {
            resident,
            needed_units: STEP_RESERVE,
        }),
        "a resident's spent pinned share parks a resident share wait"
    );
    Ok(trap)
}

/// The owner pins `resident`'s share at `units` through the owner's door.
fn pin_share(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    resident: EntityId,
    units: u64,
) -> TestResult {
    set_resident_share_as_owner(
        vault,
        owner,
        &SetResidentShareRequest {
            resident: resident.to_hex(),
            units: Some(units),
            pinned: true,
        },
    )?;
    Ok(())
}

/// The open budget trap asks, oldest first.
fn open_asks(vault: &Vault) -> Vec<DecisionAsk> {
    vault
        .decision_asks(None, 10_000, true)
        .expect("the decision asks")
        .into_iter()
        .filter(|ask| ask.queue_pin.model == BUDGET_TRAP_QUEUE)
        .collect()
}

/// The open ask about `row`'s try; panics unless exactly one is open.
fn the_ask_of(vault: &Vault, row: &AttemptRecord) -> DecisionAsk {
    let asks: Vec<DecisionAsk> = open_asks(vault)
        .into_iter()
        .filter(|ask| ask.correlation.map(|id| *id.as_bytes()) == Some(*row.id.as_bytes()))
        .collect();
    assert_eq!(
        asks.len(),
        1,
        "the parked try asks its owner once: {asks:?}"
    );
    asks.into_iter().next().expect("one ask")
}

fn choice(token: &str) -> DecisionAnswer {
    DecisionAnswer::Choice(token.to_owned())
}

/// Asserts `row`'s try still waits at its trap, leased as its host holds it.
fn assert_still_parked(vault: &Vault, row: &AttemptRecord, what: &str) -> TestResult {
    assert!(
        DreamerRunnerStore::new(vault)
            .parked_attempt(row.id)?
            .is_some(),
        "{what}: the try stays parked"
    );
    let after = AttemptQueue::new(vault)
        .get(row.id)?
        .expect("the parked try");
    assert_eq!(
        after.state.as_str(),
        "leased",
        "{what}: the try stays leased"
    );
    Ok(())
}

/// Asserts `row`'s try was woken as the same try: its park gone, its trap consumed, queued again.
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
    Ok(())
}

/// Asserts ask `seq` was withdrawn, not answered.
fn assert_withdrawn(vault: &Vault, seq: u64, what: &str) -> TestResult {
    let ask = vault.decision_ask(seq)?.expect("the ask stays on record");
    assert!(ask.withdrawn_at.is_some(), "{what} withdraws the ask");
    assert!(ask.answer.is_none(), "{what}: withdrawn, not answered");
    Ok(())
}

/// Canon: "BudgetTrap suspends background work ... and sends owner digest
/// choices". A try parked on its resident's spent pinned share asks the owner
/// once, keyed by the try, to keep it parked or approve an overdraft. With no
/// answer, and on `stay_parked`, the try stays parked.
#[test]
fn a_resident_share_park_asks_its_owner_and_stays_parked_unless_he_overdraws() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let vault = Arc::new(vault);
    let owner = owner_proof(&vault);
    let resident = EntityId::now();
    pin_share(&vault, &owner, resident, 0)?;
    let backend = AdmittingBackend::new(resident, Some(host_account(&vault)?));

    let row = leased_try(&vault, "share-ask", 1)?;
    park_on_share(&vault, &row, resident, &backend)?;
    let ask = the_ask_of(&vault, &row);
    let AnswerContract::Choice { options } = &ask.question.contract else {
        panic!(
            "a choice of what the try does, got {:?}",
            ask.question.contract
        );
    };
    assert_eq!(options, &vec!["stay_parked", "overdraft"]);
    assert_still_parked(&vault, &row, "with no answer")?;

    vault.answer_decision_ask(&owner, ask.seq, choice("stay_parked"))?;
    assert_still_parked(&vault, &row, "after stay_parked")?;
    assert!(
        open_asks(&vault).is_empty(),
        "the answered ask leaves the queue"
    );
    assert!(
        !backend.admits(),
        "the share still refuses the resident's call"
    );
    Ok(())
}

/// Ruling RUNBUDGET-OVERDRAFT = C on a resident's park: the owner's
/// `overdraft` with no cap raises the pinned share by what the refused call
/// lacked (one more call) and wakes the park in the answer's write.
#[test]
fn the_owners_overdraft_raises_the_resident_share_and_wakes_its_park() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let vault = Arc::new(vault);
    let owner = owner_proof(&vault);
    let resident = EntityId::now();
    pin_share(&vault, &owner, resident, 0)?;
    let backend = AdmittingBackend::new(resident, Some(host_account(&vault)?));

    let row = leased_try(&vault, "share-overdraft", 1)?;
    let trap = park_on_share(&vault, &row, resident, &backend)?;
    let ask = the_ask_of(&vault, &row);

    vault.answer_decision_ask(&owner, ask.seq, choice("overdraft"))?;
    assert_woken(&vault, &row, &trap, "the owner's overdraft")?;
    let share = vault
        .resident_shares()?
        .into_iter()
        .find(|read| read.resident == resident)
        .expect("the resident's share")
        .share;
    assert_eq!(
        (share.units, share.pinned),
        (Some(STEP_RESERVE), true),
        "the pinned share rises by the call it lacked"
    );
    assert!(
        backend.admits(),
        "the raised share admits the resident's call"
    );
    assert!(
        open_asks(&vault).is_empty(),
        "the answered ask leaves the queue"
    );
    Ok(())
}

/// Ruling RUNBUDGET-SCOPE = B on a spend scope's park: a try its open hard
/// root scope's cap refused asks the owner; his press of `overdraft` with a
/// cap raises the scope's cap by it and wakes the park in the answer's write.
#[test]
fn a_spend_scope_park_asks_and_the_owners_overdraft_raises_its_cap() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let owner = owner_proof(&vault);
    let dispatcher = AgentDispatcher::new(&vault);
    let scope = SpendScopeId::launch("owen-scope")?;
    dispatcher
        .open_root_spend_scope(
            scope.clone(),
            DeclaredMaximum {
                units: SCOPE_CAP,
                unit: LeaseUnit::tokens(),
            },
            Some(MaximumShown { at_ms: 10_000 }),
            10,
        )
        .expect("the root scope opens");
    let spend = llm::StepSpendScope::read_before_guards(&vault, scope.clone())?;
    let guard = dispatcher.guard_for_scope(&scope)?;
    let asked = guard.reserve_units();
    assert!(
        SCOPE_CAP < asked,
        "the scope's cap sits below the guard's reserve"
    );
    let backend = AdmittingBackend::new(EntityId::now(), None);

    let row = leased_try(&vault, "scope-overdraft", 1)?;
    let trap = trapped_step(&vault, &row, &backend, &guard, Some(spend), false);
    let park = DreamerRunnerStore::new(&vault)
        .parked_attempt(row.id)?
        .expect("the scope's park");
    assert_eq!(
        park.wait.map(|wait| wait.wait),
        Some(DreamerParkWait::Budget {
            scope: scope.clone(),
            asked_units: asked,
        }),
        "the scope's hard cap parks a budget wait on it"
    );
    let ask = the_ask_of(&vault, &row);
    assert_still_parked(&vault, &row, "with no answer")?;

    vault.press_run_budget_ask(&owner, ask.seq, RunBudgetChoice::Overdraft, Some(asked))?;
    assert_woken(&vault, &row, &trap, "the owner's overdraft")?;
    let raised = dispatcher
        .read_spend_scope(&scope)?
        .expect("the scope stays on record");
    assert_eq!(
        raised.cap_units,
        SCOPE_CAP + asked,
        "the scope's cap rises by the cap the owner named"
    );
    assert!(
        open_asks(&vault).is_empty(),
        "the answered ask leaves the queue"
    );
    Ok(())
}

/// Ruling RUNBUDGET-SCOPE = B: a try parked on its wake pass's spent guard
/// asks nothing; a later pass with room wakes it, as the owner's nightly
/// budget renews. (A guard: it holds on the base too.)
#[test]
fn a_pass_budget_park_asks_nothing() -> TestResult {
    let (_dir, vault) = open_vault()?;
    owner_proof(&vault);
    let backend = AdmittingBackend::new(EntityId::now(), None);
    let spent = llm::BudgetGuard::with_reserve_units(
        "budget-trap-ask-pass",
        0,
        STEP_RESERVE,
        llm::BudgetExhaustionPolicy::Suspend,
    );

    let row = leased_try(&vault, "pass-budget", 1)?;
    trapped_step(&vault, &row, &backend, &spent, None, true);
    let park = DreamerRunnerStore::new(&vault)
        .parked_attempt(row.id)?
        .expect("the pass's park");
    assert!(
        matches!(
            park.wait.map(|wait| wait.wait),
            Some(DreamerParkWait::PassBudget { .. })
        ),
        "the spent pass guard parks a pass budget wait"
    );
    assert!(
        open_asks(&vault).is_empty(),
        "a pass budget park asks nothing"
    );
    Ok(())
}

/// A woken park waits on no answer: the owner's release of one parked try,
/// and his share write that fits another, each withdraw that try's open ask
/// in the wake's write and leave the other's open.
#[test]
fn a_woken_park_withdraws_its_open_ask() -> TestResult {
    let (_dir, vault) = open_vault()?;
    let vault = Arc::new(vault);
    let owner = owner_proof(&vault);
    let resident = EntityId::now();
    pin_share(&vault, &owner, resident, 0)?;
    let backend = AdmittingBackend::new(resident, Some(host_account(&vault)?));

    let row_a = leased_try(&vault, "withdraw-a", 1)?;
    let trap_a = park_on_share(&vault, &row_a, resident, &backend)?;
    let row_b = leased_try(&vault, "withdraw-b", 2)?;
    let trap_b = park_on_share(&vault, &row_b, resident, &backend)?;
    let ask_a = the_ask_of(&vault, &row_a);
    let ask_b = the_ask_of(&vault, &row_b);

    let park_b = DreamerRunnerStore::new(&vault)
        .parked_attempt(row_b.id)?
        .expect("try B's park");
    let hex_b: String = row_b
        .id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let released = release_doors::release_as_owner(
        &vault,
        &owner,
        &hex_b,
        DreamerParkCauseView::from(park_b.cause),
        park_b.parked_at,
        row_b.attempt_count,
    )?;
    assert!(released.effected, "the owner's Resume queues try B");
    assert_woken(&vault, &row_b, &trap_b, "the owner's release")?;
    assert_withdrawn(&vault, ask_b.seq, "the owner's release")?;
    assert_eq!(
        open_asks(&vault)
            .iter()
            .map(|ask| ask.seq)
            .collect::<Vec<_>>(),
        vec![ask_a.seq],
        "try A's ask stays open"
    );

    pin_share(&vault, &owner, resident, STEP_RESERVE)?;
    assert_woken(&vault, &row_a, &trap_a, "the owner's share write")?;
    assert_withdrawn(&vault, ask_a.seq, "the owner's share write")?;
    assert!(open_asks(&vault).is_empty(), "no ask is left open");
    Ok(())
}
