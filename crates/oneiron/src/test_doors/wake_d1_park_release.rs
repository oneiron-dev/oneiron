//! Doors for `tests/wake_d1_park_release.rs` (#6877, WAKE-D1): the wake
//! pass's local node id, the owner notice a park waiting on the owner's
//! release raises, and the owner's release and stop. Compiled only under
//! `--cfg oneiron_test_support`; never API.

use crate::Result;
use crate::consent::AuthenticatedOwner;
use crate::dreamer_runner::{
    DreamerParkedAttemptRecord, ParkReleaseAction, ParkReleaseView, ReleaseParkedAttemptRequest,
    release_parked_attempt_as_owner,
};
use crate::entity_id::EntityId;
use crate::memory::DreamerParkCauseView;
use crate::vault::Vault;

/// This device's stable client id (`identity::load_or_mint_client_id`), which
/// a wake pass takes as its local node id.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn load_or_mint_client_id(vault: &Vault) -> Result<u64> {
    crate::identity::load_or_mint_client_id(vault)
}

/// The vault's embedded owner. Resolved before a read txn opens: the resolve
/// opens its own txn, and LMDB allows one reader slot per thread.
fn embedded_owner(vault: &Vault) -> EntityId {
    vault
        .ensure_embedded_owner_actor()
        .expect("the vault's embedded owner")
}

/// `park`'s notice source for `owner`, at the try's current lease generation.
fn park_notice_source(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    park: &DreamerParkedAttemptRecord,
    owner: &EntityId,
) -> Result<crate::inbox::NotificationSource> {
    let attempt = crate::attempt_queue::AttemptQueue::new(vault)
        .get_in_write_txn(txn, park.attempt_id)?
        .expect("the parked try");
    Ok(crate::dreamer_runner::park_release_notice_source(
        park,
        attempt.attempt_count,
        owner,
    ))
}

/// Whether the vault's embedded owner saw `park`'s release notice; `None`
/// when it was never raised.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn park_notice_seen(vault: &Vault, park: &DreamerParkedAttemptRecord) -> Result<Option<bool>> {
    let owner = embedded_owner(vault);
    let txn = vault.store.env.read_txn()?;
    let source = park_notice_source(vault, &txn, park, &owner)?;
    vault.notification_seen_in_txn(&txn, &source, &owner)
}

/// The recipient stored on the embedded owner's notice of `park`: `None` when
/// no such notice exists, `Some(None)` when it names no recipient.
///
/// # Errors
/// The store's.
#[doc(hidden)]
pub fn park_notice_recipient(
    vault: &Vault,
    park: &DreamerParkedAttemptRecord,
) -> Result<Option<Option<String>>> {
    let owner = embedded_owner(vault);
    let txn = vault.store.env.read_txn()?;
    let source = park_notice_source(vault, &txn, park, &owner)?;
    let id = crate::inbox::notification_id(&source)?;
    let crate::vault::LiveEntityRow::Live { body, .. } =
        crate::vault::live_entity_row_in_txn(&vault.store, &txn, &id)?
    else {
        return Ok(None);
    };
    Ok(Some(
        crate::inbox::decode_notification_body(&body)?.recipient,
    ))
}

/// The owner's release of the park a read showed: the try, its park's cause
/// and time, and the try's lease generation.
///
/// # Errors
/// The release's.
#[doc(hidden)]
pub fn release_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    attempt: &str,
    cause: DreamerParkCauseView,
    parked_at: u64,
    attempt_count: u32,
) -> Result<ParkReleaseView> {
    release_parked_attempt_as_owner(
        vault,
        owner,
        &ReleaseParkedAttemptRequest {
            attempt: attempt.to_owned(),
            action: ParkReleaseAction::Resume,
            cause,
            parked_at,
            attempt_count,
            note: None,
        },
    )
}

/// The owner's stop of the park a read showed: the try, its park's cause and
/// time, and the try's lease generation. Returns the try's queue state after
/// the stop.
///
/// # Errors
/// The stop's.
#[doc(hidden)]
pub fn stop_as_owner(
    vault: &Vault,
    owner: &AuthenticatedOwner,
    attempt: &str,
    cause: DreamerParkCauseView,
    parked_at: u64,
    attempt_count: u32,
) -> Result<String> {
    let view = release_parked_attempt_as_owner(
        vault,
        owner,
        &ReleaseParkedAttemptRequest {
            attempt: attempt.to_owned(),
            action: ParkReleaseAction::Stop,
            cause,
            parked_at,
            attempt_count,
            note: Some("the owner stops this run".to_owned()),
        },
    )?;
    Ok(view.state)
}

/// Writes one Pending send at sequence zero through the production ledger writer.
/// No transport is invoked.
///
/// # Errors
/// The ledger's validation or storage errors.
#[doc(hidden)]
pub fn insert_pending_send(
    vault: &Vault,
    attempt: crate::attempt_queue::AttemptId,
    now_ms: u64,
) -> Result<()> {
    let request = crate::outbound_intent_ledger::OutboundCallRequest::new(
        attempt,
        0,
        "park-stop-server",
        "park-stop-tool",
        b"stop-fixture payload".to_vec(),
        now_ms,
    );
    let pending = crate::outbound_intent_ledger::IntentLedgerRecord::pending(
        request,
        true,
        crate::outbound_intent_ledger::BudgetChargeMarker {
            key_ref: None,
            budget_class: crate::outbound_intent_ledger::BudgetClass::Send,
            matched_rows: Vec::new(),
            sends_debit: 0,
            accounted_at_ms: now_ms,
        },
    )
    .map_err(intent_ledger_error)?;
    vault.with_write_txn_grouped(|wtxn| {
        crate::outbound_intent_ledger::insert_pending_in_txn(vault, wtxn, &pending)
            .map_err(intent_ledger_error)
    })
}

/// Reads the state and recorded outcome of `attempt`'s sequence-zero send.
///
/// # Errors
/// The ledger's validation or storage errors.
#[doc(hidden)]
pub fn pending_send_state(
    vault: &Vault,
    attempt: crate::attempt_queue::AttemptId,
) -> Result<
    Option<(
        crate::outbound_intent_ledger::IntentState,
        Option<crate::outbound_intent_ledger::RecordedOutboundOutcome>,
    )>,
> {
    let txn = vault.store.env.read_txn()?;
    let row =
        crate::outbound_intent_ledger::read_intent_for_attempt_in_txn(vault, &txn, attempt, 0)
            .map_err(intent_ledger_error)?;
    Ok(row.map(|record| (record.state, record.recorded_outcome)))
}

fn intent_ledger_error(error: crate::outbound_intent_ledger::IntentLedgerError) -> crate::Error {
    match error {
        crate::outbound_intent_ledger::IntentLedgerError::Engine(error) => error,
        _ => crate::Error::CorruptedIndex("outbound intent ledger row"),
    }
}

/// Runs a supplied backend through the production step writer and pins its paid receipt.
///
/// # Errors
/// The model-step, reservation or settlement writer's validation or storage errors.
#[doc(hidden)]
pub async fn settle_paid_step(
    vault: &Vault,
    attempt: crate::attempt_queue::AttemptId,
    backend: &dyn crate::llm::LlmBackend,
    request: crate::llm::LlmRequest,
    now: u64,
) -> Result<[u8; 32]> {
    let owner = embedded_owner(vault);
    let ctx = crate::llm::DurableStepContext {
        vault,
        attempt_id: attempt,
        run_id: None,
        envelope_actor: crate::WriteActor::new(owner, crate::EdgeActorClass::Human),
        subject: owner,
        deadline: None,
        now_ms: now * 1_000,
        spend_scope: None,
    };
    let guard = crate::llm::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        crate::llm::BudgetExhaustionPolicy::Suspend,
    );
    let outcome = crate::llm::call_as_step(&ctx, backend, &guard, request)
        .await
        .map_err(|error| crate::Error::InvalidConfig(error.to_string()))?;
    let crate::llm::StepOutcome::Finished {
        binding, response, ..
    } = outcome
    else {
        return Err(crate::Error::InvalidConfig(
            "the scripted step did not finish".into(),
        ));
    };
    let store = crate::dreamer_runner::DreamerRunnerStore::new(vault);
    store.reserve_budget(crate::dreamer_runner::ReserveDreamerBudget {
        budget_id: "wake".into(),
        child_attempt: attempt,
        budget_total_units: 10_000,
        reserve_units: 100,
        now,
    })?;
    store.settle_budget_with_step_receipts(
        crate::dreamer_runner::SettleDreamerBudget {
            budget_id: "wake".into(),
            child_attempt: attempt,
            actual_units: response.usage.input.total + response.usage.output.total,
            now,
        },
        &[binding],
    )?;
    Ok(binding.step_hash)
}

/// Whether the production paid-step reader still sees this exact memo charged.
///
/// # Errors
/// The store's or the terminal memo reader's.
#[doc(hidden)]
pub fn step_charged(
    vault: &Vault,
    attempt: crate::attempt_queue::AttemptId,
    step_hash: &[u8; 32],
) -> Result<bool> {
    let txn = vault.store.env.read_txn()?;
    crate::dreamer_runner::DreamerRunnerStore::new(vault)
        .step_charge_marked_in_txn(&txn, attempt, step_hash)
}

/// Reserves a parked try's budget and retains measured spend through the
/// production failed-settlement writer, without charging it yet.
///
/// # Errors
/// The reservation's or owed-charge writer's storage and validation errors.
#[doc(hidden)]
pub fn retain_owed_charge(
    vault: &Vault,
    reservation: crate::dreamer_runner::ReserveDreamerBudget,
    owed_units: u64,
) -> Result<()> {
    let settlement = crate::dreamer_runner::SettleDreamerBudget {
        budget_id: reservation.budget_id.clone(),
        child_attempt: reservation.child_attempt,
        actual_units: owed_units,
        now: reservation.now,
    };
    let store = crate::dreamer_runner::DreamerRunnerStore::new(vault);
    assert!(matches!(
        store.reserve_budget(reservation)?,
        crate::dreamer_runner::DreamerBudgetReserveOutcome::Reserved(_)
    ));
    store.owe_unsettled_charge(&settlement, &[])
}

/// Counts all retained budget reservations naming `attempt`, on every line.
/// Production keys end in the attempt id; values use the production codec.
///
/// # Errors
/// The store's or the reservation row codec's.
#[doc(hidden)]
pub fn attempt_budget_reservation_count(
    vault: &Vault,
    attempt: crate::attempt_queue::AttemptId,
) -> Result<usize> {
    let table = crate::side_table::SideTable::<
        Vec<u8>,
        crate::dreamer_runner::DreamerBudgetReservation,
        crate::side_table::Raw,
    >::new(&crate::side_table::DREAMER_BUDGET_RESERVATION);
    let txn = vault.store.env.read_txn()?;
    Ok(table
        .scan(&vault.store, &txn)?
        .into_iter()
        .filter(|(key, _)| key.ends_with(attempt.as_bytes()))
        .count())
}

/// The state a failed settlement leaves for one paid call of a parked try (FIX 8728). A supplied backend runs
/// one step through the production step writer; the owed row a paid send writes before it goes names
/// `budget_id`; the try's budget is reserved on that line; and the step's measured usage is retained through the
/// production failed-settlement writer. The step is not pinned paid. Returns the measured units.
///
/// # Errors
/// The model-step, owed-call, reservation or owed-charge writer's validation or storage errors.
#[doc(hidden)]
pub async fn retain_owed_call_charge(
    vault: &Vault,
    attempt: crate::attempt_queue::AttemptId,
    backend: &dyn crate::llm::LlmBackend,
    request: crate::llm::LlmRequest,
    budget_id: &str,
    now: u64,
) -> Result<u64> {
    let owner = embedded_owner(vault);
    let ctx = crate::llm::DurableStepContext {
        vault,
        attempt_id: attempt,
        run_id: None,
        envelope_actor: crate::WriteActor::new(owner, crate::EdgeActorClass::Human),
        subject: owner,
        deadline: None,
        now_ms: now * 1_000,
        spend_scope: None,
    };
    let guard = crate::llm::BudgetGuard::with_reserve_units(
        "wake",
        10_000,
        100,
        crate::llm::BudgetExhaustionPolicy::Suspend,
    );
    let outcome = crate::llm::call_as_step(&ctx, backend, &guard, request)
        .await
        .map_err(|error| crate::Error::InvalidConfig(error.to_string()))?;
    let crate::llm::StepOutcome::Finished {
        binding, response, ..
    } = outcome
    else {
        return Err(crate::Error::InvalidConfig(
            "the scripted step did not finish".into(),
        ));
    };
    let units = crate::dreamer_consolidation::step_charge::usage_units(&response.usage);
    let store = crate::dreamer_runner::DreamerRunnerStore::new(vault);
    assert!(matches!(
        store.reserve_budget(crate::dreamer_runner::ReserveDreamerBudget {
            budget_id: budget_id.to_owned(),
            child_attempt: attempt,
            budget_total_units: 1_000,
            reserve_units: 100,
            now,
        })?,
        crate::dreamer_runner::DreamerBudgetReserveOutcome::Reserved(_)
    ));
    let owed = crate::dreamer_wake::owed::WakeOwedCall {
        boot: vault.active_wakes.boot(),
        line: budget_id.to_owned(),
        lease: "park-stop-lease".to_owned(),
        reserved_units: 100,
        at: now,
    };
    vault.with_write_txn_grouped(|wtxn| {
        crate::dreamer_wake::owed::put_owed_call_in_txn(
            vault,
            wtxn,
            attempt,
            &binding.step_hash,
            &owed,
        )
    })?;
    store.owe_unsettled_charge(
        &crate::dreamer_runner::SettleDreamerBudget {
            budget_id: budget_id.to_owned(),
            child_attempt: attempt,
            actual_units: units,
            now,
        },
        &[binding],
    )?;
    Ok(units)
}
