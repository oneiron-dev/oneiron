//! Threshold ladder emission for the budget meter.

use super::ledger::percent_used;
use super::state::BudgetState;
use super::templates::{BUDGET_LAND_PROMPT_TEMPLATE, BUDGET_PLAN_PROMPT_TEMPLATE};
use super::types::{
    BudgetLadderEvent, BudgetSignalDeliveryChannel, BudgetSteeringSignal, BudgetThreshold,
};

impl BudgetState {
    /// Fires the global ladder first, then row ladders. The global half is
    /// the unchanged single-pool ladder with `row_index: None`; row events
    /// follow in resolved row order, thresholds in 50/80/95 order, carrying
    /// `row_index: Some(i)` for the emitting meter's own policy table.
    pub(super) fn fire_ladder_events(&mut self) -> Vec<BudgetLadderEvent> {
        let mut events = self.fire_global_ladder_events();
        events.extend(self.fire_row_ladder_events());
        events
    }

    /// The byte-identical single-pool ladder: global `used + reserved`
    /// against the meter's own `limit_units`, `row_index: None`.
    pub(super) fn fire_global_ladder_events(&mut self) -> Vec<BudgetLadderEvent> {
        let metered_units = self.used_units.saturating_add(self.reserved_units);
        [
            BudgetThreshold::Silent50,
            BudgetThreshold::Plan80,
            BudgetThreshold::Land95,
        ]
        .into_iter()
        .filter_map(|threshold| {
            if percent_used(metered_units, self.limit_units) < threshold.percent() {
                return None;
            }
            if !self.fired_thresholds.insert(threshold) {
                return None;
            }
            Some(BudgetLadderEvent {
                threshold,
                steering: steering_signal(threshold),
                row_index: None,
            })
        })
        .collect()
    }

    /// Row ladders fire once per `(threshold, row)` — each row owns its
    /// threshold set, so the fire-once key is structural. The empty-table
    /// branch returns without a single event, keeping the single-pool
    /// meter's output exactly the global ladder.
    pub(super) fn fire_row_ladder_events(&mut self) -> Vec<BudgetLadderEvent> {
        if self.policy.is_empty() {
            return Vec::new();
        }
        let mut events = Vec::new();
        for index in 0..self.policy.rows().len() {
            let horizon = self.row_horizon(index);
            let metered_units = {
                let Some(tally) = self.row_tallies.get(index) else {
                    continue;
                };
                tally.used_units.saturating_add(tally.reserved_units)
            };
            for threshold in [
                BudgetThreshold::Silent50,
                BudgetThreshold::Plan80,
                BudgetThreshold::Land95,
            ] {
                if percent_used(metered_units, horizon) < threshold.percent() {
                    continue;
                }
                let Some(tally) = self.row_tallies.get_mut(index) else {
                    continue;
                };
                if !tally.fired_thresholds.insert(threshold) {
                    continue;
                }
                events.push(BudgetLadderEvent {
                    threshold,
                    steering: steering_signal(threshold),
                    row_index: u16::try_from(index).ok(),
                });
            }
        }
        events
    }

    /// One row's fixed ladder horizon: its own cap when present, then bounded
    /// by the shared total minus every floor this row's selector can never
    /// draw. Saturating throughout, so oversubscribed floors pin the horizon
    /// at zero — 100% depleted — instead of wrapping or panicking.
    pub(super) fn row_horizon(&self, row_index: usize) -> u64 {
        self.row_horizons.get(row_index).copied().unwrap_or(0)
    }
}

pub(super) fn steering_signal(threshold: BudgetThreshold) -> Option<BudgetSteeringSignal> {
    let template_id = threshold.template_id()?;
    let message = match threshold {
        BudgetThreshold::Silent50 => return None,
        BudgetThreshold::Plan80 => BUDGET_PLAN_PROMPT_TEMPLATE,
        BudgetThreshold::Land95 => BUDGET_LAND_PROMPT_TEMPLATE,
    };
    Some(BudgetSteeringSignal {
        threshold,
        channel: BudgetSignalDeliveryChannel::SteeringQueueNextTurn,
        template_id: template_id.to_owned(),
        message: message.to_owned(),
    })
}
