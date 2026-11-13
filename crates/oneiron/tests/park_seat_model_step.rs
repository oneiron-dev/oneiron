//! SEAT-PARK-MODEL-STEP-PATH: a Dreamer step that a login-backed model seat refuses parks its try
//! on that seat's wait, which the seat's available write wakes.
//!
//! Each case runs one Micro wake pass through `DreamerWakeDriver` over one witnessed TURN. The
//! host's partition executor (`ConsolidationExecutor`, single pass) makes the extraction call on a
//! backend that answers every call with one refusal:
//!
//! 1. A seat's spent window with a stated reset parks the try on that seat at generation 1 with
//!    the reset. A later pass and boot recovery do not resume it. The due-seat sweep wakes nothing
//!    before the reset and resumes the try once the store clock reaches it. The try's wake
//!    reservation settles in the park's own write.
//! 2. A seat's lapsed login parks the try on that seat with no reset. Time alone wakes nothing,
//!    and the seat's available write (the login restored) resumes it.
//! 3. An API key's spent window names no seat. Its try still parks as a Retry with no wait.
//! 4. A lapsed login whose refusal arrives once the call has run the pass past its deadline still
//!    parks the try on that seat (review round 1 of #7340): a checkpoint would let a later pass
//!    ask the seat again before its available write.
//!
//! Red on the head with `dreamer_seat_refusal_of_step` answering `None`: every refusal parks as
//! before (Retry, or the private Other park), so each seat-wait assert fails. Case 4 is red on
//! 41c70865b7b, where the partition's finish checkpoints an expired pass before it reads the
//! seat refusal. Doors:
//! `oneiron::test_doors::seat_park_model_step`, built only under `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::AttemptId;
use oneiron::dreamer_runner::{
    DREAMER_SERVER_PARK_OWNER, DreamerConsolidationScope, DreamerParkWait, DreamerParkedWait,
    DreamerRunnerStore, ModelSeatAvailability, ModelSeatAvailableSource, ModelSeatId, ParkResumer,
};
use oneiron::llm::SpentKind;
use oneiron::test_doors::seat_park_model_step as doors;
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, DreamerParkCause, DreamerWakeDriver,
    FatalLlmError, LlmBackend, LlmError, LlmGenerateFuture, LlmRequest, LlmStreamResult,
    RetryableLlmError, RunWakePass, Vault, VaultConfig, WakeCancellation, WakePassDeadline,
    WakeTrigger,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The store clock's time when each pass runs: before the window's reset.
const PASS_T: u64 = 1_000;
/// The reset the spent window states, in Unix seconds: far past the wall clock, so the step's
/// own read of it keeps it exactly, and past `PASS_T`, so the sweep finds it due only once the
/// store clock reaches it.
const WINDOW_RESET_T: u64 = 4_000_000_000;
/// The login-backed seat each refusal names: a neutral id outside the reserved test-id range.
const SEAT_BYTES: [u8; 16] = [0x73; 16];
/// The wake budget line every pass admits its tries on.
const WAKE_LINE: &str = "wake";
/// The fixture's reader grant actor, as the S63E consolidation door names one.
const READER: &str = "seat-park-reader";
/// The run id the partition try is enqueued and promoted under.
const RUN_ID: &str = "seat-park-run";

fn block_on_ready<F: Future>(future: F) -> F::Output {
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    let mut future = pin!(future);
    // The backend answers at once, so the pass only yields at its attempt boundaries; the bound
    // catches a future pending on anything else.
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("the wake pass is pending on something other than an attempt-boundary yield");
}

/// The pass ceiling of the frozen deadline, as the WAKE-D1 fixture sets it.
const PASS_CEILING_MS: u64 = 180_000;

/// When the pass's deadline passes, relative to the extraction call.
#[derive(Clone, Copy)]
enum PassClock {
    /// The deadline never passes during the pass.
    Open,
    /// The call runs the pass's clock to its ceiling before it answers.
    ExpiresInCall,
}

/// A frozen pass deadline, as the WAKE-D1 fixture builds one, and its elapsed clock.
fn frozen_deadline() -> (WakePassDeadline, Arc<AtomicU64>) {
    let elapsed = Arc::new(AtomicU64::new(0));
    let clock = Arc::clone(&elapsed);
    let deadline = WakePassDeadline::with_clock(
        PASS_CEILING_MS,
        Arc::new(move || clock.load(Ordering::SeqCst)),
    );
    (deadline, elapsed)
}

/// A backend that answers every call with `refusal` and counts the calls.
struct RefusingBackend {
    refusal: LlmError,
    calls: AtomicUsize,
    /// The pass's elapsed clock, run to the ceiling by each call before it answers.
    expire: Option<Arc<AtomicU64>>,
}

impl RefusingBackend {
    fn new(refusal: LlmError, expire: Option<Arc<AtomicU64>>) -> Self {
        Self {
            refusal,
            calls: AtomicUsize::new(0),
            expire,
        }
    }

    fn call(&self) -> LlmError {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(elapsed) = &self.expire {
            elapsed.store(PASS_CEILING_MS, Ordering::SeqCst);
        }
        self.refusal.clone()
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl LlmBackend for RefusingBackend {
    fn generate<'a>(
        &'a self,
        _request: LlmRequest,
        _lease: &'a BudgetLease,
    ) -> LlmGenerateFuture<'a> {
        let refusal = self.call();
        Box::pin(async move { Err(refusal) })
    }

    fn stream<'a>(&'a self, _request: LlmRequest, _lease: &'a BudgetLease) -> LlmStreamResult<'a> {
        Err(self.call())
    }
}

/// The spent window refusal: its reset stated, its seat `seat` (none for an API key).
fn spent_window(seat: Option<ModelSeatId>) -> LlmError {
    RetryableLlmError::QuotaSpent {
        kind: SpentKind::Window,
        retry_after: None,
        resets_at: vec![WINDOW_RESET_T],
        seat,
    }
    .into()
}

/// What one pass over one witnessed TURN left: the vault, its manual store clock and the try.
struct ParkedPass {
    _dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<oneiron_store::ports::manual_clock::ManualClock>,
    attempt: AttemptId,
    calls: usize,
}

/// Opens a fixture vault on a manual store clock at `PASS_T`, witnesses one TURN, enqueues its
/// Micro partition try and runs one wake pass whose extraction call `refusal` answers, its
/// deadline passing as `pass_clock` says. Asserts the pass parked exactly that try and completed
/// nothing.
fn park_one_partition_try(
    refusal: LlmError,
    pass_clock: PassClock,
) -> Result<ParkedPass, Box<dyn std::error::Error>> {
    let clock = oneiron_store::ports::manual_clock::ManualClock::new(PASS_T);
    let mut config = VaultConfig::device();
    config.store_clock = clock.bundle();
    let dir = tempfile::tempdir()?;
    let vault = doors::open_partition_vault(dir.path(), config, READER)?;
    vault.install_device_keystore(Arc::new(oneiron_keystore::MemoryKeystore::default()));
    vault
        .ensure_embedded_owner_actor()
        .expect("the embedded owner");
    let enqueued =
        doors::enqueue_witnessed_turn(&vault, "The garden gate is painted blue.", RUN_ID, PASS_T)?;
    assert_eq!(enqueued.len(), 1, "one TURN enqueues one partition try");
    let attempt = enqueued[0];

    let (deadline, elapsed) = frozen_deadline();
    let expire = match pass_clock {
        PassClock::Open => None,
        PassClock::ExpiresInCall => Some(elapsed),
    };
    let backend = RefusingBackend::new(refusal, expire);
    let guard =
        BudgetGuard::with_reserve_units(WAKE_LINE, 10_000, 100, BudgetExhaustionPolicy::Suspend);
    let mut executor = doors::PartitionPassExecutor::new(&vault, &backend, &guard, RUN_ID);
    let node_id = release_doors::load_or_mint_client_id(&vault)?;
    let mut driver = DreamerWakeDriver::new(&vault, WAKE_LINE, deadline);
    let report = block_on_ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: node_id,
            lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            now: PASS_T,
            host_scope: None,
            destination_bound: None,
        },
        &mut executor,
        &WakeCancellation::new(),
    ))?;
    assert_eq!(report.parked, 1, "the pass parks the refused partition try");
    assert_eq!(report.completed, 0, "no try completes on a refused call");
    assert!(
        DreamerRunnerStore::new(&vault)
            .parked_attempt(attempt)?
            .is_some(),
        "the pass parks the enqueued try"
    );
    let calls = backend.calls();
    assert!(calls >= 1, "the extraction call reached the backend");
    Ok(ParkedPass {
        _dir: dir,
        vault,
        clock,
        attempt,
        calls,
    })
}

/// The wake line's reservations are all settled: nothing is held for the parked try.
fn assert_reservation_settled(vault: &Vault, case: &str) -> TestResult {
    let budget = DreamerRunnerStore::new(vault)
        .budget(WAKE_LINE)?
        .expect("the wake line's budget row");
    assert_eq!(
        budget.reserved_units, 0,
        "{case}: the park's write settles the try's reservation"
    );
    assert_eq!(
        budget.remaining_units, budget.total_units,
        "{case}: a refused call spends nothing"
    );
    Ok(())
}

/// Case 1: a spent window with a stated reset parks the try on its seat until the reset passes.
#[test]
fn a_seats_spent_window_parks_the_step_on_the_seat_until_its_reset() -> TestResult {
    let seat = ModelSeatId::from_bytes(SEAT_BYTES)?;
    let pass = park_one_partition_try(spent_window(Some(seat)), PassClock::Open)?;
    let store = DreamerRunnerStore::new(&pass.vault);
    let park = store
        .parked_attempt(pass.attempt)?
        .expect("the window's park");
    let lease_generation = store
        .status(pass.attempt)?
        .expect("the try's row")
        .attempt
        .attempt_count;
    assert_eq!(
        park.cause,
        DreamerParkCause::Signal,
        "the seat park waits on a signal"
    );
    assert_eq!(
        park.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Seat {
                seat,
                generation: 1,
                reset_at_s: Some(WINDOW_RESET_T),
            },
            lease_generation,
        }),
        "the park names the seat at generation 1 with the window's reset"
    );
    assert!(
        !park.resumable_by(ParkResumer::LaterPass),
        "a later pass does not resume the seat park"
    );
    assert!(
        !park.resumable_by(ParkResumer::BootRecovery),
        "boot recovery does not resume the seat park"
    );
    assert!(
        park.resumable_by(ParkResumer::SeatAvailable),
        "the seat's available write resumes the park"
    );
    let state = pass.vault.model_seat_state(seat)?.expect("the seat's row");
    assert_eq!(
        state.availability,
        ModelSeatAvailability::Unavailable,
        "the refusal makes the seat unavailable"
    );
    assert_eq!(state.generation, 1, "the first refusal is generation 1");
    assert_eq!(
        state.reset_at_s,
        Some(WINDOW_RESET_T),
        "the seat keeps the window's reset"
    );
    assert_eq!(
        pass.vault.next_model_seat_reset_due()?,
        Some(WINDOW_RESET_T),
        "the window's reset is due on the sweep"
    );
    assert_reservation_settled(&pass.vault, "window")?;

    // Before the reset the sweep releases nothing and the park stays.
    pass.clock.set(WINDOW_RESET_T - 1);
    assert!(
        pass.vault.release_due_model_seats()?.is_empty(),
        "the sweep releases nothing before the reset"
    );
    assert_eq!(
        store.parked_attempt(pass.attempt)?,
        Some(park.clone()),
        "the park stays until the reset"
    );

    // At the reset the sweep writes the seat available and resumes the try.
    pass.clock.set(WINDOW_RESET_T);
    assert_eq!(
        pass.vault.release_due_model_seats()?,
        vec![seat],
        "the sweep releases the seat at its reset"
    );
    assert!(
        store.parked_attempt(pass.attempt)?.is_none(),
        "the seat's available write resumes the try"
    );
    let state = pass.vault.model_seat_state(seat)?.expect("the seat's row");
    assert_eq!(
        state.availability,
        ModelSeatAvailability::Available,
        "the seat is available after its reset"
    );
    assert_eq!(state.generation, 1, "the release answers generation 1");
    assert_eq!(
        pass.calls, 1,
        "the window refusal is not retried past the schedule"
    );
    Ok(())
}

/// Case 2: a lapsed login parks the try on its seat with no reset; only the restored login wakes
/// it.
#[test]
fn a_seats_lapsed_login_parks_the_step_on_the_seat_until_the_login_is_back() -> TestResult {
    let seat = ModelSeatId::from_bytes(SEAT_BYTES)?;
    let pass = park_one_partition_try(
        FatalLlmError::SeatSignedOut { seat }.into(),
        PassClock::Open,
    )?;
    let store = DreamerRunnerStore::new(&pass.vault);
    let park = store
        .parked_attempt(pass.attempt)?
        .expect("the lapsed login's park");
    let lease_generation = store
        .status(pass.attempt)?
        .expect("the try's row")
        .attempt
        .attempt_count;
    assert_eq!(
        park.cause,
        DreamerParkCause::Signal,
        "the seat park waits on a signal, not the owner's private park"
    );
    assert_eq!(
        park.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Seat {
                seat,
                generation: 1,
                reset_at_s: None,
            },
            lease_generation,
        }),
        "the park names the seat at generation 1 with no reset"
    );
    assert!(
        !park.resumable_by(ParkResumer::LaterPass),
        "a later pass does not resume the lapsed login's park"
    );
    assert!(
        !park.resumable_by(ParkResumer::BootRecovery),
        "boot recovery does not resume the lapsed login's park"
    );
    assert_eq!(
        pass.vault.next_model_seat_reset_due()?,
        None,
        "a lapsed login states no reset to sweep"
    );
    assert_reservation_settled(&pass.vault, "lapsed login")?;

    // Time alone wakes nothing: the park waits for the login, not blind.
    pass.clock.set(WINDOW_RESET_T);
    assert!(
        pass.vault.release_due_model_seats()?.is_empty(),
        "the sweep releases nothing for a seat with no reset"
    );
    assert_eq!(
        store.parked_attempt(pass.attempt)?,
        Some(park.clone()),
        "the park stays while the login is lapsed"
    );

    // The restored login's available write resumes the try.
    let resumed =
        pass.vault
            .record_model_seat_available(seat, 1, ModelSeatAvailableSource::LoginRestored)?;
    assert_eq!(
        resumed,
        vec![pass.attempt],
        "the restored login wakes the parked try"
    );
    assert!(
        store.parked_attempt(pass.attempt)?.is_none(),
        "the try is no longer parked"
    );
    let state = pass.vault.model_seat_state(seat)?.expect("the seat's row");
    assert_eq!(
        state.availability,
        ModelSeatAvailability::Available,
        "the seat is available after the login is restored"
    );
    Ok(())
}

/// Case 3: an API key's spent window names no seat, and its try still parks as a Retry.
#[test]
fn an_api_keys_spent_window_still_parks_the_step_as_a_retry() -> TestResult {
    let pass = park_one_partition_try(spent_window(None), PassClock::Open)?;
    let store = DreamerRunnerStore::new(&pass.vault);
    let park = store
        .parked_attempt(pass.attempt)?
        .expect("the API key's park");
    assert_eq!(
        park.cause,
        DreamerParkCause::Retry,
        "an API key's spent window parks as a Retry"
    );
    assert_eq!(park.wait, None, "an API key's park waits on no seat");
    let seat = ModelSeatId::from_bytes(SEAT_BYTES)?;
    assert_eq!(
        pass.vault.model_seat_state(seat)?,
        None,
        "no seat row is written for an API key"
    );
    assert_eq!(
        pass.vault.next_model_seat_reset_due()?,
        None,
        "no seat reset is due for an API key"
    );
    Ok(())
}

/// Case 4: a lapsed login whose refusal comes after the call ran the pass past its deadline still
/// parks the try on its seat, not as a checkpoint a later pass resumes blind.
#[test]
fn a_seats_lapsed_login_after_the_deadline_still_parks_the_step_on_the_seat() -> TestResult {
    let seat = ModelSeatId::from_bytes(SEAT_BYTES)?;
    let pass = park_one_partition_try(
        FatalLlmError::SeatSignedOut { seat }.into(),
        PassClock::ExpiresInCall,
    )?;
    let store = DreamerRunnerStore::new(&pass.vault);
    let park = store
        .parked_attempt(pass.attempt)?
        .expect("the late refusal's park");
    let lease_generation = store
        .status(pass.attempt)?
        .expect("the try's row")
        .attempt
        .attempt_count;
    assert_eq!(
        park.wait,
        Some(DreamerParkedWait {
            wait: DreamerParkWait::Seat {
                seat,
                generation: 1,
                reset_at_s: None,
            },
            lease_generation,
        }),
        "a refusal past the deadline parks on the seat at generation 1, not as a checkpoint"
    );
    assert_eq!(
        park.cause,
        DreamerParkCause::Signal,
        "the late refusal's park waits on a signal"
    );
    assert!(
        !park.resumable_by(ParkResumer::LaterPass),
        "a later pass does not resume the late refusal's park"
    );
    assert_reservation_settled(&pass.vault, "late lapsed login")?;
    let resumed =
        pass.vault
            .record_model_seat_available(seat, 1, ModelSeatAvailableSource::LoginRestored)?;
    assert_eq!(
        resumed,
        vec![pass.attempt],
        "the restored login wakes the try parked past the deadline"
    );
    assert_eq!(pass.calls, 1, "the late refusal is asked once");
    Ok(())
}
