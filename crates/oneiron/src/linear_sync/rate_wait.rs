//! A Linear mutation's wait for a full Rate window (FIX 8788).
//!
//! A default Rate row paces, it never denies: a mutation both actors' grants
//! allow, whose only full budget rows are Rate windows that refuse rather
//! than suspend, waits for the window rather than fail. It takes its turn in
//! one fair line per vault, keyed by the TASK revision's verified writer, so
//! one writer's backlog takes one turn in each round; then it sleeps until
//! the window opens, holding its turn and no transaction; then its admission
//! runs again in a fresh transaction, which checks everything again and
//! charges each key once. Nothing is charged while it waits, and no press is
//! asked for. A wait is bounded by the caller's deadline; a background pass
//! has none to spend, so a full window returns at once as
//! [`LinearSyncError::Waiting`]. The TASK's dirty revision and frozen
//! operation stay either way, so a pass after a restart meets the same
//! window again: no row records the wait.

use std::time::{Duration, Instant};

use crate::Vault;
use crate::connector_key::{self, BudgetBlock};
use crate::entity_id::EntityId;
use crate::error::Error;
use crate::work_line::LinePermit;

use super::effect::effect_bound_in;
use super::{LinearEffectRequest, LinearSyncError, LinearSyncResult, LinearWait};

/// The reason a mutation that waits for a full Rate window names, in its
/// dispatch result and its receipt. It asks no one for anything.
pub const LINEAR_RATE_WINDOW_REASON: &str = "gate.pending.connector_rate_window";

/// The connector a Linear mutation's budget rows are kept under: its
/// effect's channel, as the Gate names the key it governs by.
const LINEAR_CONNECTOR: &str = "linear";

/// Times in a row a window read open may meet a full one at admission before
/// the mutation leaves the rest for a later pass.
const OPEN_RECHECKS: u8 = 3;

/// One mutation's place in its Rate wait: its turn in the verified writers'
/// fair line once it has waited for one, held through the admission that
/// follows and passed to the next wait. Dropping it hands the turn on.
#[derive(Default)]
#[must_use = "a turn is held only while its holder is"]
pub struct LinearRateTurn {
    permit: Option<LinePermit>,
    open_rechecks: u8,
}

impl std::fmt::Debug for LinearRateTurn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinearRateTurn")
            .field("holds_turn", &self.permit.is_some())
            .field("open_rechecks", &self.open_rechecks)
            .finish()
    }
}

/// A full Rate window one mutation meets.
pub(crate) struct RateWindow {
    /// When every full window opens, Unix seconds on the engine's clock.
    pub(crate) next_eligible_at: u64,
    /// The TASK revision's verified writer, whose line the wait is in.
    writer: EntityId,
    /// The engine's clock when the window was read.
    now: u64,
}

/// The instant `wait` from now; now itself for a wait past what an instant
/// holds.
pub(super) fn deadline_after(wait: Duration) -> Instant {
    let now = Instant::now();
    now.checked_add(wait).unwrap_or(now)
}

fn waiting(next_eligible_at: u64) -> LinearSyncError {
    LinearSyncError::Waiting(LinearWait::RateWindow { next_eligible_at })
}

impl Vault {
    /// The full Rate window `request` meets now, read in a fresh read
    /// transaction over the rows its admission charges: the scheduler's key
    /// and the writer's, each once, and a catalog pool they share once.
    /// `None` while every key has room, for an operation admitted before
    /// (its replay charges nothing), and for a full row that does not pace,
    /// which its admission denies.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(crate) fn linear_rate_window(
        &self,
        request: &LinearEffectRequest,
    ) -> LinearSyncResult<Option<RateWindow>> {
        let txn = self.store.env.read_txn().map_err(Error::from)?;
        if effect_bound_in(self, &txn, &request.operation_id)? {
            return Ok(None);
        }
        let state = crate::task_verb::linear_effect_state_in_txn(self, &txn, request.task_ref)?;
        let Some(writer) = state.writer else {
            return Ok(None);
        };
        let connector = connector_key::normalize_connector_key(LINEAR_CONNECTOR);
        let keys = [request.scheduler_actor, writer.actor_ref]
            .map(|actor| {
                connector_key::governing_connector_key(&self.store, &txn, &connector, Some(&actor))
            })
            .into_iter()
            .collect::<crate::error::Result<Vec<_>>>()?;
        let same_key = matches!((&keys[0], &keys[1]), (Some((a, _)), Some((b, _))) if a == b);
        let shared_pool = !same_key
            && match (&keys[0], &keys[1]) {
                (Some((_, a)), Some((_, b))) => {
                    connector_key::shares_budget_pool(&self.store, &txn, a, b)?
                }
                _ => false,
            };
        let now = crate::ports::job_recorded_at_in_txn(&self.store, &txn)?;
        let mut block = BudgetBlock::Open;
        for (index, key) in keys.iter().enumerate() {
            if index == 1 && same_key {
                continue;
            }
            if let Some((key_id, key)) = key {
                block = block.and(connector_key::budget_block_pooled(
                    &self.store,
                    &txn,
                    key_id,
                    key,
                    &connector,
                    true,
                    now,
                    !(index == 1 && shared_pool),
                )?);
            }
        }
        Ok(match block {
            BudgetBlock::Paced { next_eligible_at } => Some(RateWindow {
                next_eligible_at,
                writer: writer.actor_ref,
                now,
            }),
            BudgetBlock::Open | BudgetBlock::Hard => None,
        })
    }

    /// `request`'s wait for a full Rate window, bounded by `deadline`: its
    /// fair turn among the verified writers waiting, then the window itself,
    /// with no transaction open. Returns the turn to hold through the
    /// admission that follows and to pass to the next wait; a window already
    /// open returns at once. The recorded outbound door calls it before each
    /// dispatch, and again when that dispatch names
    /// [`LINEAR_RATE_WINDOW_REASON`].
    ///
    /// # Errors
    ///
    /// [`LinearSyncError::Waiting`] when the window opens after `deadline`
    /// or the turn does not come before it: nothing was refused, and the
    /// mutation's frozen operation and dirty revision stay. Storage errors.
    pub fn linear_rate_turn(
        &self,
        request: &LinearEffectRequest,
        deadline: Instant,
        mut turn: LinearRateTurn,
    ) -> LinearSyncResult<LinearRateTurn> {
        loop {
            let Some(window) = self.linear_rate_window(request)? else {
                turn.open_rechecks = turn.open_rechecks.saturating_add(1);
                if turn.open_rechecks > OPEN_RECHECKS {
                    // Its admission keeps meeting a window this read finds
                    // open: a later pass sends it.
                    return Err(waiting(self.now_recorded_at()));
                }
                return Ok(turn);
            };
            turn.open_rechecks = 0;
            let wait = Duration::from_secs(window.next_eligible_at.saturating_sub(window.now));
            let left = deadline.saturating_duration_since(Instant::now());
            if wait > left {
                return Err(waiting(window.next_eligible_at));
            }
            if turn.permit.is_none() {
                let permit = self
                    .linear_rate_line
                    .admit_blocking_for(window.writer, left)
                    .map_err(|_| waiting(window.next_eligible_at))?;
                turn.permit = Some(permit);
                // At its turn the window is read again: others went first.
                continue;
            }
            std::thread::sleep(wait.max(Duration::from_secs(1)));
        }
    }
}
