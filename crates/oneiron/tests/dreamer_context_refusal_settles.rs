//! A Dreamer step the provider refuses for its context window settles once (Engine 21 Nov
//! 07:38): the try ends Failed with the refusal's text, and no later pass resends the
//! identical request.
//!
//! 1. A window-refused extraction step ends its try failed once: one Micro wake pass through
//!    `DreamerWakeDriver` over one witnessed TURN, the `ConsolidationExecutor` single pass, on a
//!    backend that refuses every call for its window. The step layer answers the extraction's
//!    deterministic empty fallback, which names the refusal it stood in for; the pass counts the
//!    try failed with the window's text and parks nothing; a second pass 901 s later asks the
//!    backend nothing new and the try is still failed.
//! 2. `dreamer_failed_on_refused_step` answers Failed for the window refusal in every typed
//!    shape (`Llm`, `ClassifiedLlm` and `SpentLlm` carrying it, and the legacy invalid-request
//!    detail naming it), and `None` for a rate limit and an unrelated invalid request.
//! 3. `dreamer_park_cause_of_llm` and `dreamer_park_cause_of_step` answer the private `Other`
//!    park for a window refusal, never `Retry`; a rate limit still parks as `Retry`.
//! 4. `correction_overflow` pages a scope summary correction again when the correction is a
//!    `SpentLlm` refused for the window, as for the legacy shape; a first call is no correction.
//!
//! Red on main 9ae17c14523: the extraction's empty fallback stands in for the refused call, so
//! the try never ends failed (case 1); the window refusal parks as a `Retry` (case 3), so a later
//! pass asks the backend again; `dreamer_failed_on_refused_step` answers `None` for the window
//! shapes (case 2); and the `ContextWindowExceeded` correction never re-pages (case 4), since the
//! wire types that 400 as `ContextWindowExceeded` while the recovery only reads the legacy shape.
//! The guards (rate limit, unrelated code, first call) are green on both, as is the server-error
//! cause answered beside them. Doors: `oneiron::test_doors::dreamer_context_refusal`, plus the
//! seat-park fixture doors the passing shape is copied from; built only under
//! `--cfg oneiron_test_support`.
#![cfg(oneiron_test_support)]

use std::future::Future;
use std::pin::pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use oneiron::attempt_queue::AttemptId;
use oneiron::dreamer_runner::{
    DREAMER_SERVER_PARK_OWNER, DreamerConsolidationScope, DreamerRunnerStore,
};
use oneiron::llm::{DreamerFailureClass, DreamerFailureDecision, DreamerFailureRoute};
use oneiron::model_step_context::StepEffectBinding;
use oneiron::model_step_error::DurableStepError;
use oneiron::test_doors::seat_park_model_step as doors;
use oneiron::test_doors::wake_d1_park_release as release_doors;
use oneiron::{
    BudgetExhaustionPolicy, BudgetGuard, BudgetLease, DreamerAttemptExecution, DreamerParkCause,
    DreamerWakeDriver, FatalLlmError, LlmBackend, LlmError, LlmGenerateFuture, LlmRequest,
    LlmStreamResult, LlmUsage, RetryableLlmError, RunWakePass, Vault, VaultConfig,
    WakeCancellation, WakePassDeadline, WakePassReport, WakeTrigger,
};
use oneiron_model::llm::DreamerFailurePrecedence;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The store clock's time when the first pass runs.
const PASS_T: u64 = 1_000;
/// The wake budget line every pass admits its tries on.
const WAKE_LINE: &str = "wake";
/// The fixture's reader grant actor, as the S63E consolidation door names one.
const READER: &str = "context-refusal-reader";
/// The run id the partition try is enqueued and promoted under.
const RUN_ID: &str = "context-refusal-run";
/// The pass ceiling of the frozen deadline, as the WAKE-D1 fixture sets it.
const PASS_CEILING_MS: u64 = 180_000;
/// The provider's window text every refused call carries.
const WINDOW_MESSAGE: &str = "maximum context length is 8192 tokens";

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
}

impl RefusingBackend {
    fn new(refusal: LlmError) -> Self {
        Self {
            refusal,
            calls: AtomicUsize::new(0),
        }
    }

    fn call(&self) -> LlmError {
        self.calls.fetch_add(1, Ordering::SeqCst);
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

/// The window refusal every call meets.
fn window_refusal() -> LlmError {
    FatalLlmError::ContextWindowExceeded {
        message: WINDOW_MESSAGE.into(),
    }
    .into()
}

/// What one pass over one witnessed TURN left: the vault, its manual store clock and the try.
struct RefusedPass {
    _dir: tempfile::TempDir,
    vault: Vault,
    clock: Arc<oneiron_store::ports::manual_clock::ManualClock>,
    attempt: AttemptId,
}

/// Opens a fixture vault on a manual store clock at `PASS_T`, witnesses one TURN and enqueues
/// its Micro partition try.
fn open_one_turn_vault() -> Result<RefusedPass, Box<dyn std::error::Error>> {
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
    Ok(RefusedPass {
        _dir: dir,
        vault,
        clock,
        attempt: enqueued[0],
    })
}

/// Runs one Micro wake pass at `now` whose extraction calls reach `backend`.
fn run_partition_pass(
    vault: &Vault,
    backend: &dyn LlmBackend,
    now: u64,
) -> Result<WakePassReport, Box<dyn std::error::Error>> {
    let (deadline, _elapsed) = frozen_deadline();
    let guard =
        BudgetGuard::with_reserve_units(WAKE_LINE, 10_000, 100, BudgetExhaustionPolicy::Suspend);
    let mut executor = doors::PartitionPassExecutor::new(vault, backend, &guard, RUN_ID);
    let node_id = release_doors::load_or_mint_client_id(vault)?;
    let mut driver = DreamerWakeDriver::new(vault, WAKE_LINE, deadline);
    Ok(block_on_ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: node_id,
            lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            now,
            host_scope: None,
            destination_bound: None,
        },
        &mut executor,
        &WakeCancellation::new(),
    ))?)
}

/// Case 1: a window-refused extraction step ends its try failed once, and a later pass resends
/// nothing.
#[test]
fn a_window_refused_extraction_step_ends_its_try_failed_once() -> TestResult {
    let pass = open_one_turn_vault()?;
    let backend = RefusingBackend::new(window_refusal());
    let report = run_partition_pass(&pass.vault, &backend, PASS_T)?;
    assert_eq!(report.failed, 1, "the pass counts the refused try failed");
    assert_eq!(report.parked, 0, "a window refusal parks nothing");
    assert_eq!(report.completed, 0, "no try completes on a refused call");
    let store = DreamerRunnerStore::new(&pass.vault);
    assert!(
        store.parked_attempt(pass.attempt)?.is_none(),
        "no park row exists for the failed try"
    );
    let row = store.status(pass.attempt)?.expect("the try's row").attempt;
    assert_eq!(row.state.as_str(), "failed", "the try is failed");
    let reason = row.last_error.as_deref().unwrap_or_default();
    assert!(
        reason.contains("context window exceeded"),
        "the failed row keeps the window's text, got: {reason}"
    );
    let calls = backend.calls();
    assert!(calls >= 1, "the extraction call reached the backend");

    // A second pass 901 s later resends nothing: the try stays failed.
    pass.clock.set(PASS_T + 901);
    let again = run_partition_pass(&pass.vault, &backend, PASS_T + 901)?;
    assert_eq!(
        backend.calls(),
        calls,
        "the second pass asks the backend nothing new"
    );
    assert_eq!(again.admitted, 0, "the failed try is not re-admitted");
    let row = store.status(pass.attempt)?.expect("the try's row").attempt;
    assert_eq!(row.state.as_str(), "failed", "the try is still failed");
    assert!(
        store.parked_attempt(pass.attempt)?.is_none(),
        "no park row exists after the second pass"
    );
    Ok(())
}

/// One paid step binding, as the runner tests build one: the try's id and its step hash.
fn step_binding() -> StepEffectBinding {
    StepEffectBinding {
        attempt_id: AttemptId::from_bytes(&[0x11; 16]).expect("test attempt id"),
        step_hash: [0x22; 32],
    }
}

/// A fatal failure policy, as the step tests build one.
fn failure_policy() -> DreamerFailureDecision {
    DreamerFailureDecision {
        class: DreamerFailureClass::Fatal,
        route: DreamerFailureRoute::Fallback,
        consolidation_eligible: false,
        effector_eligible: false,
        consolidation_ceiling: false,
        effector_ceiling: false,
        precedence: DreamerFailurePrecedence::NestedNarrowing,
    }
}

/// Case 2: a window refusal fails the step in every typed shape, and nothing else does.
#[test]
fn a_window_refusal_fails_the_step_in_every_typed_shape() -> TestResult {
    use oneiron::dreamer_runner::dreamer_failed_on_refused_step;

    let bindings = vec![step_binding()];
    let window = || FatalLlmError::ContextWindowExceeded {
        message: WINDOW_MESSAGE.into(),
    };
    let shapes: Vec<DurableStepError> = vec![
        DurableStepError::Llm(window().into()),
        DurableStepError::ClassifiedLlm {
            source: window().into(),
            failure_policy: failure_policy(),
        },
        DurableStepError::SpentLlm {
            source: window().into(),
            usage: Box::new(LlmUsage::zero()),
        },
        DurableStepError::Llm(
            FatalLlmError::InvalidRequestDetail {
                message: WINDOW_MESSAGE.into(),
                code: Some("context_length_exceeded".into()),
            }
            .into(),
        ),
    ];
    for error in &shapes {
        match dreamer_failed_on_refused_step(error, 7, &bindings) {
            Some(DreamerAttemptExecution::Failed {
                reason,
                completed_units,
                budget_refusal,
                step_bindings,
            }) => {
                assert_eq!(
                    reason,
                    error.to_string(),
                    "the Failed try keeps the step error's text"
                );
                assert_eq!(completed_units, 7, "the Failed try settles what it spent");
                assert!(
                    budget_refusal.is_none(),
                    "a window refusal carries no typed budget refusal"
                );
                assert_eq!(
                    step_bindings, bindings,
                    "the Failed try keeps its paid receipts"
                );
            }
            other => panic!("a window refusal ends the try Failed, got: {other:?}"),
        }
    }
    // Guards: any other model failure still parks instead of failing.
    let guards: Vec<DurableStepError> = vec![
        DurableStepError::Llm(
            RetryableLlmError::RateLimited {
                retry_after: None,
                resets_at: vec![],
            }
            .into(),
        ),
        DurableStepError::Llm(
            FatalLlmError::InvalidRequestDetail {
                message: "no such model".into(),
                code: Some("model_not_found".into()),
            }
            .into(),
        ),
    ];
    for error in &guards {
        assert!(
            dreamer_failed_on_refused_step(error, 7, &bindings).is_none(),
            "a non-window failure still parks: {error}"
        );
    }
    Ok(())
}

/// Case 3: a window refusal never parks as a Retry.
#[test]
fn a_window_refusal_never_parks_as_a_retry() {
    use oneiron::dreamer_runner::{dreamer_park_cause_of_llm, dreamer_park_cause_of_step};

    let window = LlmError::from(FatalLlmError::ContextWindowExceeded {
        message: WINDOW_MESSAGE.into(),
    });
    let legacy = LlmError::from(FatalLlmError::InvalidRequestDetail {
        message: WINDOW_MESSAGE.into(),
        code: Some("context_length_exceeded".into()),
    });
    for source in [window, legacy] {
        assert_eq!(
            dreamer_park_cause_of_llm(&source),
            DreamerParkCause::Other,
            "a window refusal parks privately, never as a Retry: {source}"
        );
        for error in [
            DurableStepError::Llm(source.clone()),
            DurableStepError::ClassifiedLlm {
                source: source.clone(),
                failure_policy: failure_policy(),
            },
            DurableStepError::SpentLlm {
                source: source.clone(),
                usage: Box::new(LlmUsage::zero()),
            },
        ] {
            assert_eq!(
                dreamer_park_cause_of_step(&error),
                DreamerParkCause::Other,
                "a window-refused step parks privately, never as a Retry: {error}"
            );
        }
    }
    // Guards: any other model failure keeps its cause on both.
    let limited = LlmError::from(RetryableLlmError::RateLimited {
        retry_after: None,
        resets_at: vec![],
    });
    assert_eq!(
        dreamer_park_cause_of_llm(&limited),
        DreamerParkCause::Retry,
        "a rate limit still parks as a Retry"
    );
    assert_eq!(
        dreamer_park_cause_of_step(&DurableStepError::Llm(limited)),
        DreamerParkCause::Retry,
        "a rate-limited step still parks as a Retry"
    );
    let down = LlmError::from(RetryableLlmError::ServerError);
    assert_eq!(
        dreamer_park_cause_of_llm(&down),
        DreamerParkCause::ProviderUnavailable,
        "a server error still parks as its provider's outage"
    );
    assert_eq!(
        dreamer_park_cause_of_step(&DurableStepError::Llm(down)),
        DreamerParkCause::ProviderUnavailable,
        "a failed step on a down provider still parks as its outage"
    );
}

/// Case 4: a scope summary correction over its window is paged again.
#[test]
fn a_scope_summary_correction_over_its_window_is_paged_again() {
    use oneiron::test_doors::dreamer_context_refusal::correction_overflow;

    let window = || FatalLlmError::ContextWindowExceeded {
        message: WINDOW_MESSAGE.into(),
    };
    let legacy = || FatalLlmError::InvalidRequestDetail {
        message: WINDOW_MESSAGE.into(),
        code: Some("context_length_exceeded".into()),
    };
    assert!(
        correction_overflow(&DurableStepError::SpentLlm {
            source: window().into(),
            usage: Box::new(LlmUsage::zero()),
        }),
        "a correction refused for the window pages again"
    );
    assert!(
        correction_overflow(&DurableStepError::SpentLlm {
            source: legacy().into(),
            usage: Box::new(LlmUsage::zero()),
        }),
        "a correction refused in the legacy shape still pages again"
    );
    assert!(
        !correction_overflow(&DurableStepError::Llm(window().into())),
        "a first call is no correction, even refused for the window"
    );
}
