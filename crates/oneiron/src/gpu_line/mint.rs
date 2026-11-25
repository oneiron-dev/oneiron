//! The mint (design pass 32, sections 4.1 and 4.3): one period record from
//! the line as it stood and the results inside the window before the period
//! started. It is a pure function of its arguments and all its arithmetic is
//! integer, so a replay gives the same economic digest.

use std::collections::BTreeMap;

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::defaults;
use super::fold::{
    AllowanceRule, AllowanceTable, BudgetPolicy, DrawStep, FamilyFloor, FamilyPayoff, FamilySeat,
    GpuLine, GpuLinePeriod, InvalidCost, PeriodAllocation, PinnedMode, RuleRef, SeatAtMint, Side,
    Track,
};
use crate::EntityId;
use crate::entity_id::bytes_to_hex_lower;
use crate::llm::run_admission::LeaseUnit;

/// The unit a line counts in when its policy names none: one GPU held for
/// one second.
pub const GPU_SECONDS: &str = "gpu_seconds";

/// The rules the mint can fund today: the starter and its two rivals.
pub const BUILT_RULES: [RuleRef; 3] = [
    RuleRef::PAYOFF_SHARE_1,
    RuleRef::EVEN_SPLIT_1,
    RuleRef::POSTERIOR_SAMPLING_1,
];

/// `payoff_share`'s weight is `(wins + 1) * 2^PAYOFF_WEIGHT_SHIFT / (cost +
/// prior)`: the scale keeps every positive weight above zero.
pub const PAYOFF_WEIGHT_SHIFT: u32 = 60;

/// What one family's rows inside the window say (section 4.3). Row M2-E
/// fills it from the line's arm rows and claims.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettledTally {
    /// Rungs confirmed a win.
    pub wins: u64,
    /// Rungs closed a loss.
    pub losses: u64,
    /// Seconds charged to the family's claims, invalid rungs left out.
    pub cost_secs: u64,
    /// Seconds charged to its rungs closed invalid. Box-lost and unattributed
    /// seconds are in no tally.
    pub invalid_secs: u64,
}

/// Why the mint wrote no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MintError {
    #[error("period_out_of_range: the period's bounds do not fit the vault clock")]
    PeriodOutOfRange,
    #[error("the allowance rule {0} is not built yet")]
    RuleNotBuilt(RuleRef),
    /// The vault clock names a period before one this line already minted:
    /// a minted line never reopens an earlier period.
    #[error("period {index} is before period {newest}, which this line already minted")]
    BehindMintedPeriod { index: u32, newest: u32 },
    /// The seats' floors do not fit their side: the line admits nothing
    /// until the owner changes it, and the shortfall is never taken from the
    /// other side.
    #[error("mint_blocked: the {side:?} side cannot fund its seats' floors and reserve")]
    Blocked { side: Side },
    /// The record's pools do not sum to the allowance. Inside the bounds of
    /// a valid line this cannot happen.
    #[error("the period's pools do not sum to its allowance")]
    Unbalanced,
}

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
    #[error(
        "the review bound and the returned-machine window last {min} to {max} seconds",
        min = defaults::NOTICE_SECS_BOUNDS.start(),
        max = defaults::NOTICE_SECS_BOUNDS.end()
    )]
    Notices,
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
    /// as [`mint_period`] picks them.
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
        if !draw_orders_valid(budget) {
            return Err(LineInvalid::DrawOrders);
        }
        if !defaults::NOTICE_SECS_BOUNDS.contains(&budget.review_overdue_secs)
            || !defaults::NOTICE_SECS_BOUNDS.contains(&budget.machine_returned_window_secs)
        {
            return Err(LineInvalid::Notices);
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

/// The id of the host allocation a line's wallet is installed as; its
/// generation is the period index plus one.
#[must_use]
pub fn line_allocation_id(project: &EntityId) -> String {
    format!("gpu-line:{}", project.to_hex())
}

/// Every field of a record the economic digest covers: all but the cohort
/// seed, its commit and `minted_at_ms`.
#[derive(Serialize)]
struct EconomicFields<'a> {
    project: &'a EntityId,
    index: u32,
    start_ms: u64,
    end_ms: u64,
    line_revision: u64,
    policy: &'a BudgetPolicy,
    seats: &'a [SeatAtMint],
    pinned_units: u64,
    unpinned_units: u64,
    floors: &'a [FamilyFloor],
    new_idea_pool: u64,
    reserve: (u64, u64),
    pinned_pool: u64,
    market_pool: u64,
    inputs: &'a [FamilyPayoff],
    inputs_cutoff_ms: u64,
    tables: &'a [AllowanceTable],
    split_remainder: u64,
    allocation: &'a PeriodAllocation,
}

/// sha256 (lower hex) of the record's economic fields as JSON, behind a
/// domain prefix.
#[must_use]
pub fn economic_digest(period: &GpuLinePeriod) -> String {
    let fields = EconomicFields {
        project: &period.project,
        index: period.index,
        start_ms: period.start_ms,
        end_ms: period.end_ms,
        line_revision: period.line_revision,
        policy: &period.policy,
        seats: &period.seats,
        pinned_units: period.pinned_units,
        unpinned_units: period.unpinned_units,
        floors: &period.floors,
        new_idea_pool: period.new_idea_pool,
        reserve: period.reserve,
        pinned_pool: period.pinned_pool,
        market_pool: period.market_pool,
        inputs: &period.inputs,
        inputs_cutoff_ms: period.inputs_cutoff_ms,
        tables: &period.tables,
        split_remainder: period.split_remainder,
        allocation: &period.allocation,
    };
    let mut hasher = Sha256::new();
    hasher.update(b"oneiron.gpu_line.period.economic:v1\n");
    hasher.update(serde_json::to_vec(&fields).expect("a period record serializes"));
    bytes_to_hex_lower(&hasher.finalize())
}

/// Whether `period`'s pools sum to its allowance (section 3.2).
#[must_use]
pub fn period_balances(period: &GpuLinePeriod) -> bool {
    let floors: u128 = period
        .floors
        .iter()
        .map(|floor| u128::from(floor.units))
        .sum();
    let tables: u128 = period
        .tables
        .iter()
        .map(|table| {
            table
                .ceilings
                .iter()
                .map(|(_, units)| u128::from(*units))
                .sum::<u128>()
                + u128::from(table.unallocated)
        })
        .sum();
    let pools = floors
        + u128::from(period.reserve.0)
        + u128::from(period.reserve.1)
        + u128::from(period.new_idea_pool)
        + u128::from(period.pinned_pool)
        + tables
        + u128::from(period.split_remainder);
    pools == u128::from(period.policy.allowance_units)
}

/// Mints the record of period `index` of `line`: the seats it funds, their
/// floors, the reserve, the new-idea pool, the pinned and market pools, and
/// one table of market ceilings per rule in force, each rule taking an equal
/// part of the market pool. `tallies` holds what the rows inside the window
/// say, by family; a family it does not name has none.
///
/// # Errors
///
/// [`MintError`]: the period does not fit the clock, a rule in force is not
/// built, the seats' floors do not fit their side (`mint_blocked`), or the
/// pools do not balance.
pub fn mint_period(
    line: &GpuLine,
    index: u32,
    tallies: &BTreeMap<EntityId, SettledTally>,
    minted_at_ms: u64,
) -> Result<GpuLinePeriod, MintError> {
    let (start_ms, end_ms) = line
        .period_bounds(index)
        .ok_or(MintError::PeriodOutOfRange)?;
    let policy = &line.budget;
    let mut funded: Vec<&FamilySeat> = line
        .families
        .iter()
        .filter(|seat| seat.funded_in(index, policy.new_idea_periods))
        .collect();
    funded.sort_by_key(|seat| seat.project);
    let floored = |seat: &&&FamilySeat| seat.track != Track::NewIdea;
    let pinned_seats = funded
        .iter()
        .filter(floored)
        .filter(|seat| policy.side_of(seat.track) == Side::Pinned)
        .count() as u64;
    let unpinned_seats = funded.iter().filter(floored).count() as u64 - pinned_seats;
    let pools =
        pools(policy, pinned_seats, unpinned_seats).map_err(|side| MintError::Blocked { side })?;
    let seats: Vec<SeatAtMint> = funded
        .iter()
        .map(|seat| SeatAtMint {
            seat: seat.seat,
            family: seat.project,
            track: seat.track,
        })
        .collect();
    let floors: Vec<FamilyFloor> = funded
        .iter()
        .filter(floored)
        .map(|seat| FamilyFloor {
            family: seat.project,
            track: seat.track,
            units: pools.floor_secs,
        })
        .collect();
    let inputs: Vec<FamilyPayoff> = funded
        .iter()
        .map(|seat| {
            let tally = tallies.get(&seat.project).copied().unwrap_or_default();
            FamilyPayoff {
                family: seat.project,
                wins: tally.wins,
                losses: tally.losses,
                cost_secs: tally.cost_secs,
                invalid_secs: tally.invalid_secs,
            }
        })
        .collect();
    // Under floor_plus_market every demand and interest seat shares the
    // market pool; under exclusive only the unpinned side's. A new idea
    // never does.
    let market_inputs: Vec<&FamilyPayoff> = funded
        .iter()
        .zip(&inputs)
        .filter(|(seat, _)| {
            seat.track != Track::NewIdea
                && (policy.pinned_mode == PinnedMode::FloorPlusMarket
                    || policy.side_of(seat.track) == Side::Unpinned)
        })
        .map(|(_, input)| input)
        .collect();
    let rules = policy.rules.len().max(1) as u64;
    let share = pools.market_pool / rules;
    let split_remainder = pools.market_pool % rules;
    let mut tables = Vec::with_capacity(policy.rules.len());
    for rule in &policy.rules {
        if !BUILT_RULES.contains(rule) {
            return Err(MintError::RuleNotBuilt(*rule));
        }
        let (ceilings, unallocated) = match rule.rule {
            AllowanceRule::PayoffShare => payoff_share(
                share,
                &market_inputs,
                policy.first_rung_secs(),
                policy.invalid_cost,
            ),
            AllowanceRule::EvenSplit => even_split(share, &market_inputs),
            AllowanceRule::PosteriorSampling => {
                posterior_sampling(share, &market_inputs, policy, &line.project, index, *rule)
            }
        };
        tables.push(AllowanceTable {
            rule: *rule,
            pool_units: share,
            ceilings,
            unallocated,
        });
    }
    let mut record = GpuLinePeriod {
        project: line.project,
        index,
        start_ms,
        end_ms,
        line_revision: line.revision,
        policy: policy.clone(),
        seats,
        pinned_units: pools.pinned_units,
        unpinned_units: pools.unpinned_units,
        floors,
        new_idea_pool: pools.new_idea_pool,
        reserve: (pools.reserve_side, pools.reserve_side),
        pinned_pool: pools.pinned_pool,
        market_pool: pools.market_pool,
        inputs,
        inputs_cutoff_ms: start_ms,
        tables,
        split_remainder,
        cohort_seed_commit: None,
        cohort_seed: None,
        allocation: PeriodAllocation {
            wallet: line.wallet.clone(),
            id: line_allocation_id(&line.project),
            generation: u64::from(index) + 1,
            units: policy.allowance_units,
        },
        economic_digest: String::new(),
        minted_at_ms,
    };
    if !period_balances(&record) {
        return Err(MintError::Unbalanced);
    }
    record.economic_digest = economic_digest(&record);
    Ok(record)
}

/// One family's cost under `invalid_cost`.
fn family_cost(input: &FamilyPayoff, invalid_cost: InvalidCost) -> u128 {
    let invalid = match invalid_cost {
        InvalidCost::CountsAsCost => input.invalid_secs,
        InvalidCost::CountsNowhere => 0,
    };
    u128::from(input.cost_secs) + u128::from(invalid)
}

/// The fewest low bits every weight drops so that `pool` times the highest
/// one, and the sum of all of them, fit a `u128`. All weights drop the same
/// bits, so their ratios hold. Inside the bounds of a valid line it is zero.
fn weight_shift(pool: u64, weights: &[u128]) -> u32 {
    let top = weights.iter().copied().max().unwrap_or(0);
    (0..u128::BITS)
        .find(|shift| {
            u128::from(pool).checked_mul(top >> shift).is_some()
                && weights
                    .iter()
                    .try_fold(0u128, |sum, weight| sum.checked_add(weight >> shift))
                    .is_some()
        })
        .unwrap_or(u128::BITS - 1)
}

/// `payoff_share@1` (section 4.3): confirmed promotions per GPU-second,
/// smoothed toward the base rate of the table's own families. Returns the
/// ceilings by family id and what nobody got.
///
/// `prior = max(first_rung_secs, C / max(W, 1))` over the families, and each
/// family's weight is `(wins + 1) * 2^60 / (cost + prior)`. The pool is
/// divided by weight, rounding down; the seconds left go one each to the
/// largest remainders, ties to the lowest family id. A family with no
/// history scores exactly the base rate. With no family the whole pool is
/// unallocated.
#[must_use]
pub fn payoff_share(
    pool: u64,
    families: &[&FamilyPayoff],
    first_rung_secs: u64,
    invalid_cost: InvalidCost,
) -> (Vec<(EntityId, u64)>, u64) {
    if families.is_empty() {
        return (Vec::new(), pool);
    }
    let total_cost: u128 = families
        .iter()
        .map(|input| family_cost(input, invalid_cost))
        .sum();
    let total_wins: u128 = families.iter().map(|input| u128::from(input.wins)).sum();
    let prior = u128::from(first_rung_secs)
        .max(total_cost / total_wins.max(1))
        .max(1);
    let weights: Vec<u128> = families
        .iter()
        .map(|input| {
            let wins = u128::from(input.wins) + 1;
            let scaled = wins
                .checked_shl(PAYOFF_WEIGHT_SHIFT)
                .filter(|scaled| scaled >> PAYOFF_WEIGHT_SHIFT == wins)
                .unwrap_or(u128::MAX);
            scaled / (family_cost(input, invalid_cost) + prior)
        })
        .collect();
    let shift = weight_shift(pool, &weights);
    let weights: Vec<u128> = weights.iter().map(|weight| weight >> shift).collect();
    let sum: u128 = weights.iter().sum();
    if sum == 0 {
        return (
            families.iter().map(|input| (input.family, 0)).collect(),
            pool,
        );
    }
    let mut shares: Vec<(EntityId, u64, u128)> = families
        .iter()
        .zip(&weights)
        .map(|(input, weight)| {
            let scaled = u128::from(pool) * weight;
            let units = u64::try_from(scaled / sum).unwrap_or(pool);
            (input.family, units, scaled % sum)
        })
        .collect();
    let given: u64 = shares.iter().map(|(_, units, _)| *units).sum();
    let mut leftover = pool.saturating_sub(given);
    shares.sort_by(|left, right| right.2.cmp(&left.2).then(left.0.cmp(&right.0)));
    for share in &mut shares {
        if leftover == 0 {
            break;
        }
        share.1 += 1;
        leftover -= 1;
    }
    let mut ceilings: Vec<(EntityId, u64)> = shares
        .into_iter()
        .map(|(family, units, _)| (family, units))
        .collect();
    ceilings.sort_by_key(|(family, _)| *family);
    (ceilings, leftover)
}

/// `even_split@1` (section 4.3): the pool divided evenly over the families.
/// Returns the ceilings by family id and what nobody got.
///
/// Each family gets `pool / n`; the remainder, fewer seconds than families,
/// is unallocated. It reads no input. With no family the whole pool is
/// unallocated.
#[must_use]
pub fn even_split(pool: u64, families: &[&FamilyPayoff]) -> (Vec<(EntityId, u64)>, u64) {
    if families.is_empty() {
        return (Vec::new(), pool);
    }
    let count = families.len() as u64;
    let per = pool / count;
    let mut ceilings: Vec<(EntityId, u64)> =
        families.iter().map(|input| (input.family, per)).collect();
    ceilings.sort_by_key(|(family, _)| *family);
    (ceilings, pool - count * per)
}

/// `posterior_sampling@1` (section 4.3): it gives uncertain families more
/// tries. Returns the ceilings by family id and what nobody got.
///
/// The pool is divided into `min(pool / first_rung_secs, posterior_max_slots)`
/// slots of `pool / slots` seconds; each slot goes to one family. Per slot
/// and family the mint draws `w + l + 1` u64 values from the BLAKE3 XOF keyed
/// by (line, period, rule, slot, family) and takes the `(w + 1)`-th smallest
/// as the family's score, a discrete stand-in for a Beta(w + 1, l + 1) sample.
/// The slot goes to the largest score, ties to the lowest family id. Wins and
/// losses past `posterior_max_evidence` are scaled down together. It reads
/// wins and losses only, never cost. With no family, or no slot, the whole
/// pool is unallocated.
#[must_use]
pub fn posterior_sampling(
    pool: u64,
    families: &[&FamilyPayoff],
    policy: &BudgetPolicy,
    line: &EntityId,
    period: u32,
    rule: RuleRef,
) -> (Vec<(EntityId, u64)>, u64) {
    if families.is_empty() {
        return (Vec::new(), pool);
    }
    let cap = u128::from(policy.posterior_max_evidence);
    let mut ordered: Vec<(&FamilyPayoff, u64, u64)> = Vec::with_capacity(families.len());
    for input in families {
        let wins = u128::from(input.wins);
        let losses = u128::from(input.losses);
        let (scaled_wins, scaled_losses) = if wins + losses > cap {
            let total = wins + losses;
            (wins * cap / total, losses * cap / total)
        } else {
            (wins, losses)
        };
        ordered.push((*input, scaled_wins as u64, scaled_losses as u64));
    }
    ordered.sort_by_key(|(input, _, _)| input.family);
    let first = policy.first_rung_secs();
    let slots = if first == 0 {
        0
    } else {
        (pool / first).min(u64::from(policy.posterior_max_slots))
    };
    if slots == 0 {
        let ceilings: Vec<(EntityId, u64)> = ordered
            .iter()
            .map(|(input, _, _)| (input.family, 0))
            .collect();
        return (ceilings, pool);
    }
    let slot_secs = pool / slots;
    let mut won = vec![0u64; ordered.len()];
    let mut draws: Vec<u64> = Vec::with_capacity(cap as usize + 1);
    let mut byte_buf = [0u8; 8];
    for slot in 0..slots {
        let mut best = 0usize;
        let mut best_theta = 0u64;
        for (index, entry) in ordered.iter().enumerate() {
            let (input, scaled_wins, scaled_losses) = entry;
            let count = (*scaled_wins as usize) + (*scaled_losses as usize) + 1;
            draws.clear();
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"oneiron.gpu_line.posterior_sampling:v1");
            hasher.update(line.as_bytes());
            hasher.update(&period.to_le_bytes());
            hasher.update(rule.rule.as_str().as_bytes());
            hasher.update(&rule.version.to_le_bytes());
            hasher.update(&slot.to_le_bytes());
            hasher.update(input.family.as_bytes());
            let mut xof = hasher.finalize_xof();
            for _ in 0..count {
                xof.fill(&mut byte_buf);
                draws.push(u64::from_le_bytes(byte_buf));
            }
            let theta = *draws.select_nth_unstable(*scaled_wins as usize).1;
            if index == 0 || theta > best_theta {
                best = index;
                best_theta = theta;
            }
        }
        won[best] += 1;
    }
    let ceilings: Vec<(EntityId, u64)> = ordered
        .iter()
        .zip(won.iter())
        .map(|(entry, count)| (entry.0.family, (*count) * slot_secs))
        .collect();
    (ceilings, pool - slots * slot_secs)
}
