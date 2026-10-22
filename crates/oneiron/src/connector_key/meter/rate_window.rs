//! Whether a key's exhausted rows only pace its next effect (FIX 8788).
//!
//! A Rate row that refuses on exhaustion (the default) paces: the effect
//! waits for the row's window to open again, and its key is never charged
//! while it waits. Every other exhausted row (Sends, Spend, a Rate row the
//! owner set to suspend) denies as it always did. The first exhausted row is
//! not enough: every matched row of the key and of its catalog's shared pool
//! is read, so a hard cap is never mistaken for a wait.

use super::{
    BudgetRowState, SECONDS_PER_DAY, calendar_window_start, catalog_budget_pool_in_txn,
    load_budget_row_states,
};
use crate::connector_key::record::{
    CalendarPeriod, ConnectorKeyRecord, EffectorBudgetDimension, EffectorBudgetOnExhaust,
    EffectorBudgetWindow,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::Store;

/// What a key's budget rows say of one more effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BudgetBlock {
    /// No matched row is exhausted.
    Open,
    /// Every exhausted row paces: the effect's windows all open again at
    /// `next_eligible_at`, Unix seconds on the engine's clock.
    Paced { next_eligible_at: u64 },
    /// An exhausted row that does not pace: the effect is denied.
    Hard,
}

impl BudgetBlock {
    /// Both blocks at once: a hard row wins, and a wait lasts until the
    /// later window opens.
    #[must_use]
    pub(crate) fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Hard, _) | (_, Self::Hard) => Self::Hard,
            (
                Self::Paced {
                    next_eligible_at: a,
                },
                Self::Paced {
                    next_eligible_at: b,
                },
            ) => Self::Paced {
                next_eligible_at: a.max(b),
            },
            (paced @ Self::Paced { .. }, Self::Open) | (Self::Open, paced @ Self::Paced { .. }) => {
                paced
            }
            (Self::Open, Self::Open) => Self::Open,
        }
    }
}

/// The block one more effect meets on `key_id`'s rows at `now` and, when
/// `pool`, on its catalog's shared pool: the rows
/// [`super::preflight_effector_budgets_pooled`] reads, all of them.
#[expect(clippy::too_many_arguments)]
pub(crate) fn budget_block_pooled(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    record: &ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
    pool: bool,
) -> Result<BudgetBlock> {
    let own = key_block(store, txn, key_id, record, effect_channel, send_like, now)?;
    if !pool {
        return Ok(own);
    }
    let Some((catalog_id, catalog, channel)) = catalog_budget_pool_in_txn(store, txn, record)?
    else {
        return Ok(own);
    };
    Ok(own.and(key_block(
        store,
        txn,
        &catalog_id,
        &catalog,
        &channel,
        send_like,
        now,
    )?))
}

fn key_block(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    key_id: &EntityId,
    record: &ConnectorKeyRecord,
    effect_channel: &str,
    send_like: bool,
    now: u64,
) -> Result<BudgetBlock> {
    let states = load_budget_row_states(
        store,
        txn,
        key_id,
        record,
        Some(effect_channel),
        send_like,
        now,
    )?;
    let mut block = BudgetBlock::Open;
    for state in states.iter().filter(|state| state.matched) {
        let used = state.usage.used();
        let exhausted = match state.budget.dimension {
            EffectorBudgetDimension::Spend => used >= state.budget.limit,
            _ => used.saturating_add(state.amount) > state.budget.limit,
        };
        if !exhausted {
            continue;
        }
        let paces = state.budget.dimension == EffectorBudgetDimension::Rate
            && state.budget.on_exhaust == EffectorBudgetOnExhaust::Refuse;
        block = block.and(
            paces
                .then(|| next_eligible(state, now))
                .flatten()
                .map_or(BudgetBlock::Hard, |next_eligible_at| BudgetBlock::Paced {
                    next_eligible_at,
                }),
        );
    }
    Ok(block)
}

/// When `state`'s window next has room for its amount: once enough of its
/// live usage expires, oldest first (a rolling window), or when its next
/// bucket starts (a calendar one). `None` when no window ever holds the
/// amount alone.
fn next_eligible(state: &BudgetRowState<'_>, now: u64) -> Option<u64> {
    let limit = state.budget.limit;
    if state.amount > limit {
        return None;
    }
    match &state.budget.window {
        EffectorBudgetWindow::Rolling { duration_s } => {
            let mut entries = state.usage.entries.clone();
            entries.sort_unstable();
            let mut used = state.usage.used();
            for (at, amount) in entries {
                used = used.saturating_sub(amount);
                if used.saturating_add(state.amount) <= limit {
                    return Some(at.saturating_add(*duration_s).max(now));
                }
            }
            Some(now)
        }
        EffectorBudgetWindow::Calendar { period, .. } => {
            let start = calendar_window_start(*period, now);
            Some(match period {
                CalendarPeriod::Day => start.saturating_add(SECONDS_PER_DAY),
                CalendarPeriod::Week => start.saturating_add(7 * SECONDS_PER_DAY),
                CalendarPeriod::Month => calendar_window_start(
                    CalendarPeriod::Month,
                    start.saturating_add(32 * SECONDS_PER_DAY),
                ),
            })
        }
    }
}
