//! The draw order and the draw plan of one ask for room (design pass 32,
//! section 4.2).

use serde::{Deserialize, Serialize};

use super::room::{Bucket, Draw, DrawSource, PeriodRoom};
use super::types::{DrawStep, Track};
use crate::EntityId;

/// What a draw is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DrawPurpose {
    /// The first allowance an arm holds from its admission.
    FirstAllowanceHold,
    /// A unit at rung `rung` (1 is the first rung).
    Unit { rung: u8 },
}

/// One ask for room.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrawAsk {
    pub arm: EntityId,
    pub family: EntityId,
    /// The family's seat track now.
    pub track: Track,
    pub purpose: DrawPurpose,
    pub units: u64,
}

/// The draw order did not cover an ask; nothing may be written.
#[derive(
    Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error, schemars::JsonSchema,
)]
#[error("budget_denied: {short:?} is spent; {fits} units fit now")]
pub struct BudgetDenied {
    /// The last bucket of the order: the one that ran out. `None` when the
    /// ask may draw no bucket at all.
    pub short: Option<Bucket>,
    /// Each bucket of the order with its room before the ask.
    pub room: Vec<(Bucket, u64)>,
    /// The largest ask that fits now: the order's room summed.
    pub fits: u64,
}

/// The buckets an ask may draw, in order: the track's draw order in the
/// period's policy, at rung 1 or at a later rung. A first-allowance hold
/// takes the rung-1 order after its own step. Whatever the order names, the
/// pinned pool pays only the policy's pinned track, and a new idea draws at
/// rung 1 only (section 4.2, `new_idea_rung_one_only`: its later rungs draw
/// nothing). The rung cap binds before this and the wallet after it; neither
/// is checked here.
#[must_use]
pub fn draw_order(room: &PeriodRoom, ask: &DrawAsk) -> Vec<Bucket> {
    let policy = &room.period().policy;
    let Some(order) = policy.draw_order_of(ask.track) else {
        return Vec::new();
    };
    let steps = match ask.purpose {
        DrawPurpose::Unit { rung: 1 } | DrawPurpose::FirstAllowanceHold => &order.first_rung,
        DrawPurpose::Unit { .. } if ask.track == Track::NewIdea => return Vec::new(),
        DrawPurpose::Unit { .. } => &order.later_rungs,
    };
    steps
        .iter()
        .filter_map(|step| match step {
            DrawStep::FirstAllowance => (ask.purpose != DrawPurpose::FirstAllowanceHold)
                .then_some(Bucket::FirstAllowance { arm: ask.arm }),
            DrawStep::Floor => Some(Bucket::Floor { family: ask.family }),
            DrawStep::Pinned => (ask.track == policy.pinned_track).then_some(Bucket::Pinned),
            DrawStep::Market => room.market_rule(&ask.arm).map(|rule| Bucket::Market {
                family: ask.family,
                rule,
            }),
        })
        .collect()
}

/// The draws that cover `ask.units` in the order of [`draw_order`], each
/// bucket taken as far as its room goes. Draws of zero units are left out.
///
/// # Errors
///
/// [`BudgetDenied`] when the order's room does not cover the ask.
pub fn plan_draws(room: &PeriodRoom, ask: &DrawAsk) -> Result<Vec<Draw>, BudgetDenied> {
    let order = draw_order(room, ask);
    let mut remaining = ask.units;
    let mut draws = Vec::new();
    let mut rooms = Vec::with_capacity(order.len());
    for bucket in &order {
        let left = room.left(*bucket);
        rooms.push((*bucket, left));
        let take = left.min(remaining);
        if take > 0 {
            let source = match *bucket {
                Bucket::FirstAllowance { .. } => DrawSource::FirstAllowance,
                Bucket::Floor { .. } => DrawSource::Floor,
                Bucket::Pinned => DrawSource::Pinned,
                Bucket::Market { rule, .. } => DrawSource::Market { rule },
            };
            draws.push(Draw {
                source,
                units: take,
            });
            remaining -= take;
        }
    }
    if remaining == 0 {
        return Ok(draws);
    }
    let fits = rooms
        .iter()
        .fold(0u64, |sum, (_, left)| sum.saturating_add(*left));
    let short = order.last().copied();
    Err(BudgetDenied {
        short,
        room: rooms,
        fits,
    })
}
