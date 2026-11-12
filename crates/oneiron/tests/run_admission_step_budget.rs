//! Row B4 of BUDGET-TRAP-UNTYPED-NO-SENDER (D3): the host's run admission tells a durable step why
//! it refused a host-paid call, and the step answers by the write that can free it.
//!
//! - No allocation of the host funds the call (none delivered, the allocation spent or another
//!   wallet's, or a price past its unit): `BudgetDenied::Unfunded`. No write funds it, so the step
//!   refuses `Unfunded`, typed, with no trap and no park.
//! - The owner pinned the resident's share below what the call needs:
//!   `BudgetDenied::ResidentShareSpent`. The step parks a `ResidentShare` wait at its budget trap.
//!   The owner's share write that fits the call wakes it in that write; a share still short, or
//!   another resident's share, does not. The owner's release frees it as well.
//!
//! Each step goes through the public `call_as_step` with a step guard that has room, over a
//! backend that runs the host's run admission (`RunAdmission::admit`) for a host-paid offer and
//! answers its refusal as the model error it reads as. Trap states and the owner's release go
//! through `oneiron::test_doors`, built only under `--cfg oneiron_test_support`:
//! `RUSTFLAGS="--cfg oneiron_test_support" cargo test --locked -p oneiron --all-features
//! --test run_admission_step_budget`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::{AttemptQueue, AttemptRecord, ClaimAttempt, ClaimOutcome};
use oneiron::dreamer_runner::{
    DREAMER_CONSOLIDATION_MICRO_ATTEMPT_KIND, DREAMER_SERVER_PARK_OWNER, DreamerConsolidationScope,
    DreamerParkWait, DreamerParkedWait, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt, ParkResumer,
};
use oneiron::edge::EdgeActorClass;
use oneiron::llm;
use oneiron::llm::run_admission::resident_doors::{
    SetResidentShareRequest, set_resident_share_as_owner,
};
use oneiron::llm::run_admission::{
    Allocation, AllocationRef, AllocationRefusal, BudgetLine, HostAccount, KeyCustody, LeaseUnit,
    MemoryReceipts, OfferBinding, OfferRoute, Payer, RunAdmission, RunCall, RunDeclaration,
    RunDenied, UnitRate,
};
use oneiron::memory::DreamerParkCauseView;
use oneiron::store::model_step_submission::StepBudgetRefusal;
use oneiron::test_doors::park_typed_wait as doors;
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{EntityId, Vault, VaultConfig, WriteActor};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The model every request and offer here names.
const MODEL: &str = "test/model@r1";
/// What each call reserves, in tokens: on the step's guard, the run's line and the allocation.
const STEP_RESERVE: u64 = 500;
/// Room enough for every call here on the step's guard and the run's line.
const ROOM_UNITS: u64 = 10_000;
/// The host's allocation, in tokens: far more than any call here asks.
const ALLOCATION_UNITS: u64 = 100_000;

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
    panic!("a host-paid step pending on something other than its backend's answer");
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

/// A declared run on a token line with room for every call here; `host` pays its host-paid calls.
fn host_paid_run(name: &str, host: Option<Arc<HostAccount>>) -> RunAdmission {
    RunAdmission::new(
        name,
        RunDeclaration::declared(BudgetLine {
            limit_units: ROOM_UNITS,
            reserve_units: STEP_RESERVE,
            unit: LeaseUnit::tokens(),
        }),
        host,
        Arc::new(MemoryReceipts::default()),
    )
}

/// A host-paid model backend: it runs the host's run admission for each call, as a gated backend
/// does before it sends, and answers a refusal as the model error the refusal reads as. It sends
/// nothing: an admitted call answers a fatal error, which no step here reaches.
struct AdmittingBackend {
    run: RunAdmission,
    offer: OfferBinding,
    calls: AtomicUsize,
}

impl AdmittingBackend {
    fn new(run: RunAdmission) -> Self {
        Self {
            run,
            offer: host_offer(),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Whether the run admission admits one more call of the step's request now.
    fn admits(&self) -> bool {
        let request = paid_step_request("host-paid step");
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
        self.calls.fetch_add(1, Ordering::SeqCst);
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

/// Runs one host-paid step of `row`'s try, bound to its wake pass as every Dreamer host's step is,
/// under a step guard with room, so only the run admission below the backend can refuse it.
fn host_paid_step(
    vault: &Vault,
    row: &AttemptRecord,
    now_ms: u64,
    backend: &AdmittingBackend,
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
        wake_pass_bound: true,
    };
    let guard = llm::BudgetGuard::with_reserve_units(
        "run-admission-step",
        ROOM_UNITS,
        STEP_RESERVE,
        llm::BudgetExhaustionPolicy::Suspend,
    );
    block_on_ready(llm::call_as_step(
        &ctx,
        backend,
        &guard,
        paid_step_request("host-paid step"),
    ))
}

/// Asserts the refused step left nothing: no park, its try still leased as its host holds it.
fn assert_nothing_parked(vault: &Vault, row: &AttemptRecord, what: &str) -> TestResult {
    assert!(
        DreamerRunnerStore::new(vault)
            .parked_attempt(row.id)?
            .is_none(),
        "{what}: a refused step parks nothing"
    );
    let after = AttemptQueue::new(vault)
        .get(row.id)?
        .expect("the refused step's try");
    assert_eq!(
        after.state.as_str(),
        "leased",
        "{what}: a refused step leaves its try leased, for its host to end"
    );
    assert_eq!(
        after.lease_owner.as_deref(),
        Some(DREAMER_SERVER_PARK_OWNER),
        "{what}: a refused step leaves its try's lease as it was"
    );
    Ok(())
}

/// Parks `row`'s try on its resident's spent share: the run admission refuses its host-paid step.
/// Asserts the park's wait and its resumers, and returns its trap.
fn park_on_share(
    vault: &Vault,
    row: &AttemptRecord,
    resident: EntityId,
    backend: &AdmittingBackend,
) -> Result<llm::TrapRef, Box<dyn std::error::Error>> {
    let outcome = host_paid_step(vault, row, 1_000, backend);
    let trap = match outcome {
        Ok(llm::StepOutcome::Trapped { trap, .. }) => trap,
        other => panic!("a resident's spent pinned share traps the step: got {other:?}"),
    };
    assert_eq!(
        trap.kind,
        llm::DreamerTrapKind::Budget,
        "the resident's step parks at a budget trap"
    );
    let park = DreamerRunnerStore::new(vault)
        .parked_attempt(row.id)?
        .expect("the resident's step park");
    assert_eq!(
        park.park_owner,
        llm::trap_park_owner(&trap.trap_claim_id),
        "the resident's step park sits under its trap's owner"
    );
    assert_eq!(
        park.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::ResidentShare {
                resident,
                needed_units: STEP_RESERVE,
            },
            lease_generation: row.attempt_count,
        }),
        "a resident's spent pinned share parks a resident share wait naming the share the call needed"
    );
    for resumer in ParkResumer::ALL {
        assert_eq!(
            park.resumable_by(resumer),
            matches!(
                resumer,
                ParkResumer::ResidentShareRaise
                    | ParkResumer::TrapConsume
                    | ParkResumer::OwnerRelease
            ),
            "only the owner's share write, its trap consume or the owner's release resumes a resident share park ({resumer:?})"
        );
    }
    Ok(trap)
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

/// Asserts `row`'s try still waits at its trap, leased as its host holds it.
fn assert_still_parked(vault: &Vault, row: &AttemptRecord, what: &str) -> TestResult {
    assert!(
        DreamerRunnerStore::new(vault)
            .parked_attempt(row.id)?
            .is_some(),
        "{what} leaves the resident's park"
    );
    let after = AttemptQueue::new(vault)
        .get(row.id)?
        .expect("the parked try");
    assert_eq!(
        after.state.as_str(),
        "leased",
        "{what} leaves the parked try leased"
    );
    Ok(())
}

/// The owner pins `resident`'s share at `units` through the owner's door.
fn pin_share(
    vault: &Vault,
    owner: &oneiron::consent::AuthenticatedOwner,
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

fn attempt_hex(row: &AttemptRecord) -> String {
    row.id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[test]
fn the_run_admission_names_an_unfunded_call_and_a_spent_resident_share() {
    for denied in [RunDenied::NoAllocation, RunDenied::AllocationExhausted] {
        assert_eq!(
            llm::LlmError::from(denied.clone()),
            llm::LlmError::BudgetDenied(llm::BudgetDenied::Unfunded),
            "a host-paid call no allocation funds reads as unfunded, never as a spent budget ({denied:?})"
        );
    }
    let resident = EntityId::now();
    assert_eq!(
        llm::LlmError::from(RunDenied::ResidentShareSpent {
            resident,
            needed_units: 7,
        }),
        llm::LlmError::BudgetDenied(llm::BudgetDenied::ResidentShareSpent {
            resident,
            needed_units: 7,
        }),
        "a resident's spent pinned share keeps its resident and the share the call needed"
    );
    assert_eq!(
        llm::LlmError::from(RunDenied::AllocationRefused {
            reason: AllocationRefusal::HostCheck,
        }),
        llm::LlmError::BudgetDenied(llm::BudgetDenied::HostCheck),
        "a host check stays the account owner's question"
    );

    // A price past its meter's unit: no allocation holds it.
    let credits = LeaseUnit::new("credits").expect("unit");
    let run = RunAdmission::new(
        "price-overflow",
        RunDeclaration::declared(BudgetLine {
            limit_units: ROOM_UNITS,
            reserve_units: 2,
            unit: credits.clone(),
        }),
        None,
        Arc::new(MemoryReceipts::default()),
    );
    let offer = OfferBinding {
        payer: Payer::CustomerKey,
        rates: vec![UnitRate {
            unit: credits,
            per: 1,
            cost: u64::MAX,
        }],
        ..host_offer()
    };
    let request = paid_step_request("price overflow");
    match run.admit(RunCall {
        selector: None,
        request: &request,
        offer: &offer,
    }) {
        Err(denied) => assert_eq!(
            denied,
            RunDenied::Budget {
                denied: llm::BudgetDenied::Unfunded,
            },
            "a price past its meter's unit is unfunded"
        ),
        Ok(_) => panic!("a price past its meter's unit is refused"),
    }
}

#[test]
fn a_host_paid_step_no_allocation_funds_refuses_unfunded_and_parks_nothing() -> TestResult {
    let (_dir, vault) = open_vault()?;
    // An account the host granted nothing, and a run with no host account (a self-hosted vault).
    for (tag, host) in [
        ("ungranted", Some(HostAccount::new())),
        ("no-account", None),
    ] {
        let row = leased_try(&vault, tag, 1)?;
        let backend = AdmittingBackend::new(host_paid_run(tag, host));
        match host_paid_step(&vault, &row, 1_000, &backend) {
            Err(llm::DurableStepError::BudgetRefused(refusal)) => assert_eq!(
                refusal,
                StepBudgetRefusal::Unfunded {
                    asked_units: Some(STEP_RESERVE),
                },
                "{tag}: the step refuses unfunded, naming its reservation"
            ),
            other => panic!(
                "{tag}: a host-paid step no allocation funds refuses typed, with no trap: got {other:?}"
            ),
        }
        assert_eq!(
            backend.calls(),
            1,
            "{tag}: the step's call met the run admission once"
        );
        assert_nothing_parked(&vault, &row, tag)?;
    }
    Ok(())
}

#[test]
fn a_resident_step_under_its_pinned_share_parks_until_the_owners_share_write_fits_it() -> TestResult
{
    let (_dir, vault) = open_vault()?;
    let vault = Arc::new(vault);
    let owner = embedded_owner_proof(&vault);
    let resident = EntityId::now();
    let account = HostAccount::with_residents(llm::VaultResidentLedger::new(Arc::clone(&vault)));
    account.grant(Allocation {
        reference: AllocationRef {
            id: "allocation-1".to_owned(),
            generation: 1,
        },
        units: ALLOCATION_UNITS,
        unit: LeaseUnit::tokens(),
        wallet: None,
    })?;
    pin_share(&vault, &owner, resident, 0)?;
    let backend = AdmittingBackend::new(
        host_paid_run("resident-share", Some(account)).initiated_by(Some(resident)),
    );

    // 1. The pinned share refuses both tries' host-paid steps: each parks a resident share wait.
    let row_a = leased_try(&vault, "resident-share-a", 1)?;
    let trap_a = park_on_share(&vault, &row_a, resident, &backend)?;
    let row_b = leased_try(&vault, "resident-share-b", 2)?;
    let trap_b = park_on_share(&vault, &row_b, resident, &backend)?;
    assert!(
        !backend.admits(),
        "the run admission still refuses the resident's call"
    );

    // 2. A share write still short of the call, and another resident's share write, wake nothing.
    pin_share(&vault, &owner, resident, STEP_RESERVE - 1)?;
    assert_still_parked(&vault, &row_a, "a share write still short of the call")?;
    assert_still_parked(&vault, &row_b, "a share write still short of the call")?;
    pin_share(&vault, &owner, EntityId::now(), ALLOCATION_UNITS)?;
    assert_still_parked(&vault, &row_a, "another resident's share write")?;
    assert_still_parked(&vault, &row_b, "another resident's share write")?;

    // 3. The owner's release frees a resident share park too: Resume wakes its trap.
    let store = DreamerRunnerStore::new(&vault);
    let park_b = store
        .parked_attempt(row_b.id)?
        .expect("try B's resident share park");
    let released = release_doors::release_as_owner(
        &vault,
        &owner,
        &attempt_hex(&row_b),
        DreamerParkCauseView::from(park_b.cause),
        park_b.parked_at,
        row_b.attempt_count,
    );
    let released = match released {
        Ok(released) => released,
        Err(error) => panic!("the owner's Resume serves a resident share park: got {error:?}"),
    };
    assert!(
        released.effected,
        "the owner's Resume of a resident share park queues it"
    );
    assert_woken(
        &vault,
        &row_b,
        &trap_b,
        "the owner's Resume of a resident share park",
    )?;

    // 4. The owner's share write that fits the call wakes the park in that write, and the run
    // admission now admits the resident's call.
    pin_share(&vault, &owner, resident, STEP_RESERVE)?;
    assert_woken(
        &vault,
        &row_a,
        &trap_a,
        "the owner's share write that fits the call",
    )?;
    assert!(backend.admits(), "the share that fits the call admits it");
    Ok(())
}
