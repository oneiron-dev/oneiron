//! Doors for `tests/park_seat_model_step.rs` (SEAT-PARK-MODEL-STEP-PATH): a
//! vault whose Micro consolidation extracts on this server, one witnessed
//! TURN enqueued as a Micro partition try, and the host's partition executor
//! over a test's backend for a wake pass. Thin wrappers over production APIs
//! only. Compiled only under `--cfg oneiron_test_support` (`test_doors`);
//! hidden, never API.

use std::future::Future;
use std::path::Path;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use crate::attempt_queue::AttemptId;
use crate::dreamer_consolidation::{
    ConsolidationDecisions, ConsolidationExecutor, enqueue_partition_attempts, read_watermark,
    scan_dirty_turns,
};
use crate::dreamer_promotion::{DreamerRunContext, PromotionWriterSink};
use crate::dreamer_runner::{
    DREAMER_SERVER_PARK_OWNER, DreamerRunnerStore, EnqueueDreamerAttemptOutcome,
    EnqueueDreamerConsolidationAttempt, ModelSeatId,
};
use crate::dreamer_wake::DreamerAttemptExecutor;
use crate::dreamer_wake::{
    DreamerWakeDriver, RunWakePass, WakeCancellation, WakePassDeadline, WakeTrigger,
};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::llm::{HostInferenceBinding, HostInferenceContext};
use crate::vault::Vault;
use crate::{
    BudgetGuard, DreamerAdmittedAttempt, DreamerAttemptExecution, DreamerClaimAuthoringStrategy,
    DreamerConsolidationScope, LlmBackend, LlmRequest, ModelId, ModelLocality, VaultConfig,
    WakeAttemptContext,
};

/// The model every partition call names.
const PARTITION_MODEL: &str = "test/model@r1";

/// The witnessed TURN's occurrence, as the S63E consolidation door sets it.
const TURN_OCCURRED_AT: u64 = 10;

/// How many dirty TURNs one enqueue reads.
const DIRTY_TURN_LIMIT: usize = 10;

fn allow_partition_extraction(_: &LlmRequest) -> bool {
    true
}

/// Opens a vault at `path` under `config` for a Micro consolidation pass:
/// engine machines provisioned, extraction allowed on this server, and the
/// shipped policy plus a `core:read` grant for actor `reader`.
///
/// # Errors
///
/// The vault's.
#[doc(hidden)]
pub fn open_partition_vault(path: &Path, config: VaultConfig, reader: &str) -> Result<Vault> {
    let vault = Vault::open(path, config)?;
    crate::test_fixtures::provision_engine_machines(&vault);
    super::consolidation::allow_own_server_extraction(&vault)?;
    super::consolidation::shipped_policy_with_reader(&vault, reader)?;
    Ok(vault)
}

/// Witnesses `words` as one visible user MESSAGE in a fresh TURN and
/// enqueues the Micro partition tries that consolidate the dirty TURNs,
/// under `run_id` at `now`. Answers the tries' ids.
///
/// # Errors
///
/// The vault's, or a witness the memory door refuses.
#[doc(hidden)]
pub fn enqueue_witnessed_turn(
    vault: &Vault,
    words: &str,
    run_id: &str,
    now: u64,
) -> Result<Vec<AttemptId>> {
    super::consolidation::witness_user_turn(vault, EntityId::now(), words, None, TURN_OCCURRED_AT)?;
    let scope = DreamerConsolidationScope::Micro;
    let watermark = read_watermark(vault, scope)?;
    let dirty = scan_dirty_turns(vault, scope, &watermark, DIRTY_TURN_LIMIT)?;
    Ok(
        enqueue_partition_attempts(vault, scope, &dirty, &watermark, run_id, now)?
            .into_iter()
            .map(|outcome| match outcome {
                EnqueueDreamerAttemptOutcome::Enqueued(status)
                | EnqueueDreamerAttemptOutcome::Existing(status) => status.attempt.id,
            })
            .collect(),
    )
}

/// The host's partition executor for one wake pass: a single-pass,
/// unbound `ConsolidationExecutor` per admitted try, its calls on `backend`
/// under `guard`, landing through the promotion writer.
#[doc(hidden)]
pub struct PartitionPassExecutor<'a> {
    vault: &'a Vault,
    backend: &'a dyn LlmBackend,
    guard: &'a BudgetGuard,
    run_id: String,
}

impl<'a> PartitionPassExecutor<'a> {
    /// An executor over `backend` and `guard` whose promotions carry `run_id`.
    #[doc(hidden)]
    #[must_use]
    pub fn new(
        vault: &'a Vault,
        backend: &'a dyn LlmBackend,
        guard: &'a BudgetGuard,
        run_id: &str,
    ) -> Self {
        Self {
            vault,
            backend,
            guard,
            run_id: run_id.to_owned(),
        }
    }
}

impl DreamerAttemptExecutor for PartitionPassExecutor<'_> {
    async fn execute(
        &mut self,
        attempt: &DreamerAdmittedAttempt,
        ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        let actor = self.vault.dreamer_authority()?;
        let model = ModelId::new(PARTITION_MODEL)
            .map_err(|_| Error::InvalidConfig("partition model id".into()))?;
        let mut sink = PromotionWriterSink::new(
            self.vault,
            DreamerRunContext {
                run_id: self.run_id.clone(),
                attempt_id: attempt.status.attempt.id,
                agent_actor: actor,
                now_ms: ctx.now_ms,
            },
        );
        let mut inner = ConsolidationExecutor {
            roles: Default::default(),
            backend: self.backend,
            guard: self.guard,
            strategy: DreamerClaimAuthoringStrategy::SinglePass,
            actor,
            model: model.clone(),
            inference: HostInferenceContext {
                binding: HostInferenceBinding::Advertised {
                    model,
                    locality: ModelLocality::OwnServer,
                    keyless: false,
                },
                extraction_egress: Some(&allow_partition_extraction),
            },
            sink: &mut sink,
            scope: None,
            decisions: ConsolidationDecisions::shipped()?,
        };
        DreamerAttemptExecutor::execute(&mut inner, attempt, ctx).await
    }
}

/// A stub executor that refuses every admitted try on one seat, as a spent
/// model seat's step does.
struct SeatRefusal {
    seat: ModelSeatId,
    reset_at_s: Option<u64>,
}

impl DreamerAttemptExecutor for SeatRefusal {
    async fn execute(
        &mut self,
        _attempt: &DreamerAdmittedAttempt,
        _ctx: &mut WakeAttemptContext<'_>,
    ) -> Result<DreamerAttemptExecution> {
        Ok(DreamerAttemptExecution::ParkOnSeat {
            reason: "model seat refused the step".to_owned(),
            seat: *self.seat.as_bytes(),
            reset_at_s: self.reset_at_s,
        })
    }
}

/// Polls `future` until it is ready: the wake pass yields only at its
/// attempt boundaries.
fn ready<F: Future>(future: F) -> F::Output {
    let mut cx = Context::from_waker(Waker::noop());
    let mut future = pin!(future);
    for _ in 0..10_000 {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
    }
    panic!("the seat park pass is pending on something other than an attempt boundary");
}

/// Enqueues one Micro try under `tag` and runs one wake pass at `now`, leased
/// under the server's park owner, whose executor refuses it on `seat` with
/// `reset_at_s`: the driver parks the try on the seat's wait, as a spent
/// seat's step does. Answers the try.
///
/// # Errors
///
/// The vault's, or a pass that does not park the try.
#[doc(hidden)]
pub fn park_try_on_seat(
    vault: &Vault,
    seat: ModelSeatId,
    reset_at_s: Option<u64>,
    tag: &str,
    now: u64,
) -> Result<AttemptId> {
    let store = DreamerRunnerStore::new(vault);
    let (EnqueueDreamerAttemptOutcome::Enqueued(status)
    | EnqueueDreamerAttemptOutcome::Existing(status)) =
        store.enqueue_consolidation(EnqueueDreamerConsolidationAttempt {
            scope: DreamerConsolidationScope::Micro,
            input: rmpv::Value::from(format!("input:{tag}")),
            parent_attempt: None,
            dedupe_key: Some(tag.to_owned()),
            run_id: None,
            now,
        })?;
    let attempt = status.attempt.id;
    let mut driver = DreamerWakeDriver::new(
        vault,
        "wake",
        WakePassDeadline::with_clock(180_000, std::sync::Arc::new(|| 0)),
    );
    ready(driver.run_wake_pass(
        RunWakePass {
            trigger: WakeTrigger::Compaction,
            scope: DreamerConsolidationScope::Micro,
            local_node_id: crate::identity::load_or_mint_client_id(vault)?,
            lease_owner: DREAMER_SERVER_PARK_OWNER.to_owned(),
            budget_total_units: 10_000,
            reserve_units: 100,
            now,
            host_scope: None,
            destination_bound: None,
        },
        &mut SeatRefusal { seat, reset_at_s },
        &WakeCancellation::new(),
    ))?;
    if store.parked_attempt(attempt)?.is_none() {
        return Err(Error::InvalidConfig(
            "the seat park pass did not park the try".into(),
        ));
    }
    Ok(attempt)
}
