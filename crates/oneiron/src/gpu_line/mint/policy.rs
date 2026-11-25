//! What a line must hold before the mint funds it: its unit, rules, pools,
//! floors and draw orders (design pass 32, sections 3.1 and 4.1).

use super::period::MintError;
use crate::gpu_line::defaults;
use crate::gpu_line::fold::{BudgetPolicy, DrawStep, FamilySeat, GpuLine, RuleRef, Side, Track};
use crate::llm::run_admission::LeaseUnit;

/// The unit a line counts in when its policy names none: one GPU held for
/// one second.
pub const GPU_SECONDS: &str = "gpu_seconds";

/// The rules the mint can fund today: the starter, its two rivals and the proposed table.
pub const BUILT_RULES: [RuleRef; 4] = [
    RuleRef::PAYOFF_SHARE_1,
    RuleRef::EVEN_SPLIT_1,
    RuleRef::POSTERIOR_SAMPLING_1,
    RuleRef::PROPOSED_1,
];

/// Why a line cannot be set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineInvalid {
    #[error("a GPU line names its unit in lowercase ASCII letters, digits, `_` and `-`")]
    Unit,
    #[error("a GPU line names a wallet with a nonempty issuer and id")]
    Wallet,
    #[error(
        "a period lasts {min} to {max} seconds and fits the vault clock",
        min = defaults::PERIOD_SECS_BOUNDS.start(),
        max = defaults::PERIOD_SECS_BOUNDS.end()
    )]
    Period,
    #[error(
        "a GPU line allows {min} to {max} units a period",
        min = defaults::ALLOWANCE_UNITS_BOUNDS.start(),
        max = defaults::ALLOWANCE_UNITS_BOUNDS.end()
    )]
    Allowance,
    #[error(
        "the pinned parts are a fraction p/q with p < q <= {max}",
        max = defaults::MAX_PINNED_DENOMINATOR
    )]
    PinnedParts,
    #[error("the pinned track is demand or interest")]
    PinnedTrack,
    #[error(
        "a GPU line caps {min} to {max} rungs, each at least 1 second and at least the one \
         before, the last at most the allowance",
        min = defaults::RUNG_COUNT_BOUNDS.start(),
        max = defaults::RUNG_COUNT_BOUNDS.end()
    )]
    RungCaps,
    #[error("a floor holds at most {max} rung-1 allowances", max = defaults::MAX_FLOOR_ARMS)]
    FloorArms,
    #[error(
        "a period funds at most {max} new-idea seats, and at least the new ideas seated now",
        max = defaults::MAX_NEW_IDEA_SLOTS_PER_PERIOD
    )]
    NewIdeaSlots,
    #[error(
        "a new idea is funded for {min} to {max} periods",
        min = defaults::NEW_IDEA_PERIODS_BOUNDS.start(),
        max = defaults::NEW_IDEA_PERIODS_BOUNDS.end()
    )]
    NewIdeaPeriods,
    #[error(
        "a GPU line funds {min} to {max} distinct allowance rules",
        min = defaults::RULE_COUNT_BOUNDS.start(),
        max = defaults::RULE_COUNT_BOUNDS.end()
    )]
    Rules,
    #[error(transparent)]
    RuleNotBuilt(MintError),
    #[error(
        "the window holds {min} to {max} periods",
        min = defaults::WINDOW_PERIODS_BOUNDS.start(),
        max = defaults::WINDOW_PERIODS_BOUNDS.end()
    )]
    Window,
    #[error(
        "posterior_sampling@1 takes {slots_min} to {slots_max} slots and {evidence_min} to \
         {evidence_max} wins plus losses a family",
        slots_min = defaults::POSTERIOR_MAX_SLOTS_BOUNDS.start(),
        slots_max = defaults::POSTERIOR_MAX_SLOTS_BOUNDS.end(),
        evidence_min = defaults::POSTERIOR_MAX_EVIDENCE_BOUNDS.start(),
        evidence_max = defaults::POSTERIOR_MAX_EVIDENCE_BOUNDS.end()
    )]
    PosteriorSampling,
    #[error("a line's proposal_fallback is a built rule other than proposed@1")]
    ProposalFallback,
    #[error(
        "a proposal's reason limit is {min} to {max} bytes",
        min = defaults::PROPOSAL_WHY_MAX_BYTES_BOUNDS.start(),
        max = defaults::PROPOSAL_WHY_MAX_BYTES_BOUNDS.end()
    )]
    ProposalWhy,
    #[error(
        "the draw orders name each track once; each order names a pool once, and the first \
         allowance only at the head of the rung-1 order"
    )]
    DrawOrders,
    #[error("each offer is named once and is not blank")]
    Offers,
    #[error("each machine is named once")]
    Machines,
    #[error("each Grant is named once in each role list")]
    Roles,
    /// The seats' floors and the reserve do not fit their side.
    #[error("policy_unfunded: the {side:?} side cannot fund its seats' floors and reserve")]
    Unfunded { side: Side },
}

/// A period's pools (section 4.1), before any rule divides the market pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pools {
    pub pinned_units: u64,
    pub unpinned_units: u64,
    pub floor_secs: u64,
    /// Per side.
    pub reserve_side: u64,
    pub new_idea_pool: u64,
    pub pinned_pool: u64,
    pub market_pool: u64,
}

/// The pools of a period under `policy` with `pinned_seats` and
/// `unpinned_seats` floors to fund on each side.
///
/// # Errors
///
/// The side whose floors, reserve (and, on the unpinned side, the new-idea
/// pool) do not fit.
pub fn pools(policy: &BudgetPolicy, pinned_seats: u64, unpinned_seats: u64) -> Result<Pools, Side> {
    let pinned_units = policy.pinned_units();
    let unpinned_units = policy.allowance_units.saturating_sub(pinned_units);
    let floor = policy.floor_secs();
    let reserve_side = u128::from(policy.seat_reserve_floors) * floor;
    let new_idea_pool = u128::from(policy.new_idea_slots_per_period) * floor;
    let pinned_pool = u128::from(pinned_units)
        .checked_sub(floor * u128::from(pinned_seats) + reserve_side)
        .ok_or(Side::Pinned)?;
    let market_pool = u128::from(unpinned_units)
        .checked_sub(floor * u128::from(unpinned_seats) + reserve_side + new_idea_pool)
        .ok_or(Side::Unpinned)?;
    // Each of these is at most the allowance, which is a u64.
    let fit = |units: u128| u64::try_from(units).unwrap_or(u64::MAX);
    Ok(Pools {
        pinned_units,
        unpinned_units,
        floor_secs: fit(floor),
        reserve_side: fit(reserve_side),
        new_idea_pool: fit(new_idea_pool),
        pinned_pool: fit(pinned_pool),
        market_pool: fit(market_pool),
    })
}

/// Whether `items` names each entry once.
fn distinct<T: Ord>(items: &[T]) -> bool {
    let mut sorted: Vec<&T> = items.iter().collect();
    sorted.sort_unstable();
    sorted.windows(2).all(|pair| pair[0] != pair[1])
}

/// Whether `policy`'s draw orders name each track once, each pool once per
/// order, and the first allowance only at the head of a rung-1 order.
fn draw_orders_valid(policy: &BudgetPolicy) -> bool {
    let tracks: Vec<Track> = policy.draw_orders.iter().map(|order| order.track).collect();
    distinct(&tracks)
        && [Track::Demand, Track::Interest, Track::NewIdea]
            .iter()
            .all(|track| tracks.contains(track))
        && policy.draw_orders.iter().all(|order| {
            distinct(&order.first_rung)
                && distinct(&order.later_rungs)
                && !order.later_rungs.contains(&DrawStep::FirstAllowance)
                && order
                    .first_rung
                    .iter()
                    .skip(1)
                    .all(|step| *step != DrawStep::FirstAllowance)
        })
}

impl GpuLine {
    /// The seats the mint of period `index` lists under this line's policy,
    /// as [`mint_period`](super::mint_period) picks them.
    fn seats_funded_in(&self, index: u32) -> impl Iterator<Item = &FamilySeat> {
        let new_idea_periods = self.budget.new_idea_periods;
        self.families
            .iter()
            .filter(move |seat| seat.funded_in(index, new_idea_periods))
    }

    /// The seats the mint of period `index` funds a floor for, on (pinned,
    /// unpinned) side; new ideas are paid from their own pool.
    #[must_use]
    pub fn side_seats(&self, index: u32) -> (u64, u64) {
        let mut sides = (0, 0);
        for seat in self
            .seats_funded_in(index)
            .filter(|seat| seat.track != Track::NewIdea)
        {
            match self.budget.side_of(seat.track) {
                Side::Pinned => sides.0 += 1,
                Side::Unpinned => sides.1 += 1,
            }
        }
        sides
    }

    /// The new-idea seats the mint of period `index` funds.
    #[must_use]
    pub fn new_idea_seats(&self, index: u32) -> u64 {
        self.seats_funded_in(index)
            .filter(|seat| seat.track == Track::NewIdea)
            .count() as u64
    }

    /// Checks every rule a line must keep before it is stored: the bounds of
    /// section 3.1, and that the mint of `next_period`, the first one the
    /// policy applies to, funds every seat it lists. A seat that lapses
    /// before that mint counts for none of it.
    ///
    /// # Errors
    ///
    /// The first rule it breaks.
    pub fn validate(&self, next_period: u32) -> Result<(), LineInvalid> {
        let budget = &self.budget;
        if LeaseUnit::new(self.unit.as_str()).is_err() {
            return Err(LineInvalid::Unit);
        }
        if !self.wallet.is_valid() {
            return Err(LineInvalid::Wallet);
        }
        if !defaults::PERIOD_SECS_BOUNDS.contains(&self.period_secs)
            || self.period_bounds(0).is_none()
        {
            return Err(LineInvalid::Period);
        }
        if !defaults::ALLOWANCE_UNITS_BOUNDS.contains(&budget.allowance_units) {
            return Err(LineInvalid::Allowance);
        }
        let (numerator, denominator) = budget.pinned_parts;
        if numerator >= denominator || denominator > defaults::MAX_PINNED_DENOMINATOR {
            return Err(LineInvalid::PinnedParts);
        }
        if budget.pinned_track == Track::NewIdea {
            return Err(LineInvalid::PinnedTrack);
        }
        let caps = &budget.rung_caps_secs;
        if !defaults::RUNG_COUNT_BOUNDS.contains(&caps.len())
            || caps.first().is_none_or(|first| *first == 0)
            || caps.windows(2).any(|pair| pair[1] < pair[0])
            || caps
                .last()
                .is_none_or(|last| *last > budget.allowance_units)
        {
            return Err(LineInvalid::RungCaps);
        }
        if budget.floor_arms > defaults::MAX_FLOOR_ARMS {
            return Err(LineInvalid::FloorArms);
        }
        if budget.new_idea_slots_per_period > defaults::MAX_NEW_IDEA_SLOTS_PER_PERIOD
            || self.new_idea_seats(next_period) > u64::from(budget.new_idea_slots_per_period)
        {
            return Err(LineInvalid::NewIdeaSlots);
        }
        if !defaults::NEW_IDEA_PERIODS_BOUNDS.contains(&budget.new_idea_periods) {
            return Err(LineInvalid::NewIdeaPeriods);
        }
        if !defaults::RULE_COUNT_BOUNDS.contains(&budget.rules.len()) || !distinct(&budget.rules) {
            return Err(LineInvalid::Rules);
        }
        if let Some(rule) = budget.rules.iter().find(|rule| !BUILT_RULES.contains(rule)) {
            return Err(LineInvalid::RuleNotBuilt(MintError::RuleNotBuilt(*rule)));
        }
        if !defaults::WINDOW_PERIODS_BOUNDS.contains(&budget.window_periods) {
            return Err(LineInvalid::Window);
        }
        if !defaults::POSTERIOR_MAX_SLOTS_BOUNDS.contains(&budget.posterior_max_slots)
            || !defaults::POSTERIOR_MAX_EVIDENCE_BOUNDS.contains(&budget.posterior_max_evidence)
        {
            return Err(LineInvalid::PosteriorSampling);
        }
        if budget.proposal_fallback == RuleRef::PROPOSED_1
            || !BUILT_RULES.contains(&budget.proposal_fallback)
        {
            return Err(LineInvalid::ProposalFallback);
        }
        if !defaults::PROPOSAL_WHY_MAX_BYTES_BOUNDS.contains(&budget.proposal_why_max_bytes) {
            return Err(LineInvalid::ProposalWhy);
        }
        if !draw_orders_valid(budget) {
            return Err(LineInvalid::DrawOrders);
        }
        if !distinct(&self.offers) || self.offers.iter().any(|offer| offer.trim().is_empty()) {
            return Err(LineInvalid::Offers);
        }
        if !distinct(&self.machines) {
            return Err(LineInvalid::Machines);
        }
        if !distinct(&self.leads) || !distinct(&self.reviewers) || !distinct(&self.planners) {
            return Err(LineInvalid::Roles);
        }
        let (pinned_seats, unpinned_seats) = self.side_seats(next_period);
        pools(budget, pinned_seats, unpinned_seats)
            .map_err(|side| LineInvalid::Unfunded { side })?;
        Ok(())
    }

    /// The window of period `index`: results whose work falls in
    /// `[from, to)` are its inputs.
    #[must_use]
    pub fn window_of(&self, index: u32) -> Option<(u64, u64)> {
        let (start, _) = self.period_bounds(index)?;
        let span = self
            .period_ms()?
            .checked_mul(u64::from(self.budget.window_periods))?;
        Some((start.saturating_sub(span), start))
    }
}
