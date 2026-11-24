//! The mint (design pass 32, sections 4.1 and 4.3): one period record from
//! the line as it stood and the outcomes settled before the period started.
//! It is a pure function of its arguments and all its arithmetic is integer,
//! so a replay gives the same bytes.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::fold::{
    AllowanceRule, AllowanceTable, FamilyFloor, FamilyPayoff, FamilySeat, GpuLine, GpuLinePeriod,
    InvalidCost, PayoffSeed, PinnedMode, RuleRef, Track,
};
use crate::EntityId;
use crate::entity_id::bytes_to_hex_lower;

/// The unit every line counts in: one GPU held for one second.
pub const GPU_SECONDS: &str = "gpu_seconds";

/// The rules the mint can fund today. `posterior_sampling@1` and
/// `even_split@1` join with row M2-G.
pub const BUILT_RULES: [RuleRef; 1] = [RuleRef::PAYOFF_SHARE_1];

/// The scale of a `payoff_share` score: confirmed promotions per GPU-second
/// are small numbers, so the integer score keeps twelve decimal places.
pub const PAYOFF_SCORE_SCALE: u128 = 1_000_000_000_000;

/// A family with no win anywhere on the line is smoothed toward this many
/// rung-1 caps per win.
pub const NO_WIN_PRIOR_RUNGS: u64 = 4;

/// The most rules a line funds at once: the starter, and one rival for the
/// comparison.
pub const MAX_RULES: usize = 2;

/// The most wins a family's seed may carry.
pub const MAX_SEED_WINS: u64 = 10_000;
/// The most losses a family's seed may carry.
pub const MAX_SEED_LOSSES: u64 = 10_000;
/// The most GPU-seconds a family's seed may carry: about 31.7 GPU-years.
pub const MAX_SEED_COST_SECS: u64 = 1_000_000_000;
/// The most periods a seed stays among the mint's inputs.
pub const MAX_SEED_WEIGHT_PERIODS: u32 = 52;
/// The longest origin a seed may name, in bytes.
pub const MAX_SEED_ORIGIN_BYTES: usize = 1_024;

/// What the outcomes settled inside the window say about one family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SettledTally {
    /// Settled outcomes with `success = true`.
    pub wins: u64,
    /// Settled outcomes with `success = false`.
    pub losses: u64,
    /// Seconds charged to its measurable closed rungs.
    pub cost_secs: u64,
    /// Seconds charged to its invalid rungs. Box-lost seconds are in no
    /// tally.
    pub invalid_secs: u64,
}

/// Why the mint wrote no record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum MintError {
    #[error("the period's bounds do not fit the vault clock")]
    PeriodOutOfRange,
    #[error("the allowance rule {0} is not built yet")]
    RuleNotBuilt(RuleRef),
    /// The vault clock names a period before one this line already minted:
    /// the clock went back, and a minted line never reopens an earlier
    /// period.
    #[error("period {index} is before period {newest}, which this line already minted")]
    BehindMintedPeriod { index: u32, newest: u32 },
}

/// Why a line cannot be set.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LineInvalid {
    #[error("a GPU line counts in gpu_seconds, not {0}")]
    Unit(String),
    #[error("a GPU line names a wallet with a nonempty issuer and id")]
    Wallet,
    #[error("a GPU line names the fleet's --who")]
    FleetWho,
    #[error("a period lasts at least one second and fits the vault clock")]
    Period,
    #[error("a GPU line allows at least one unit a period")]
    Allowance,
    #[error("the pinned parts must divide: a nonzero denominator at least the numerator")]
    PinnedParts,
    #[error("a GPU line caps at least one rung, each above zero and above the one before")]
    RungCaps,
    #[error("a GPU line funds one or two allowance rules, each once")]
    Rules,
    #[error(transparent)]
    RuleNotBuilt(MintError),
    #[error("the window holds at least one period")]
    Window,
    #[error("each host is named once and is not blank")]
    Hosts,
    #[error(
        "a payoff seed carries at most {wins} wins, {losses} losses and {cost} seconds, stays 1 \
         to {periods} periods and names an origin of 1 to {origin} bytes",
        wins = MAX_SEED_WINS,
        losses = MAX_SEED_LOSSES,
        cost = MAX_SEED_COST_SECS,
        periods = MAX_SEED_WEIGHT_PERIODS,
        origin = MAX_SEED_ORIGIN_BYTES
    )]
    Seed,
    #[error("the seated families' floors do not fit their own side of the allowance")]
    FloorsDoNotFit,
}

impl PayoffSeed {
    /// Whether the seed keeps the bounds a line admits.
    #[must_use]
    pub fn is_bounded(&self) -> bool {
        self.wins <= MAX_SEED_WINS
            && self.losses <= MAX_SEED_LOSSES
            && self.cost_secs <= MAX_SEED_COST_SECS
            && (1..=MAX_SEED_WEIGHT_PERIODS).contains(&self.weight_periods)
            && !self.origin.trim().is_empty()
            && self.origin.len() <= MAX_SEED_ORIGIN_BYTES
    }
}

impl GpuLine {
    /// Checks every rule a line must keep before it is stored.
    ///
    /// # Errors
    ///
    /// The first rule it breaks.
    pub fn validate(&self) -> Result<(), LineInvalid> {
        if self.unit.as_str() != GPU_SECONDS {
            return Err(LineInvalid::Unit(self.unit.as_str().to_owned()));
        }
        if !self.wallet.is_valid() {
            return Err(LineInvalid::Wallet);
        }
        if self.fleet_who.trim().is_empty() {
            return Err(LineInvalid::FleetWho);
        }
        if self.period_secs == 0 || self.period_bounds(0).is_none() {
            return Err(LineInvalid::Period);
        }
        if self.allowance_units == 0 {
            return Err(LineInvalid::Allowance);
        }
        let (numerator, denominator) = self.pinned_parts;
        if denominator == 0 || numerator > denominator {
            return Err(LineInvalid::PinnedParts);
        }
        if self.rung_caps_secs.first().is_none_or(|first| *first == 0)
            || self
                .rung_caps_secs
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(LineInvalid::RungCaps);
        }
        let mut rules = self.rules.clone();
        rules.sort();
        rules.dedup();
        if self.rules.is_empty() || self.rules.len() > MAX_RULES || rules.len() != self.rules.len()
        {
            return Err(LineInvalid::Rules);
        }
        if let Some(rule) = self.rules.iter().find(|rule| !BUILT_RULES.contains(rule)) {
            return Err(LineInvalid::RuleNotBuilt(MintError::RuleNotBuilt(*rule)));
        }
        if self.window_periods == 0 {
            return Err(LineInvalid::Window);
        }
        let mut hosts: Vec<&str> = self.hosts.iter().map(String::as_str).collect();
        hosts.sort_unstable();
        hosts.dedup();
        if hosts.len() != self.hosts.len() || hosts.iter().any(|host| host.trim().is_empty()) {
            return Err(LineInvalid::Hosts);
        }
        if self
            .families
            .iter()
            .any(|seat| seat.seed.as_ref().is_some_and(|seed| !seed.is_bounded()))
        {
            return Err(LineInvalid::Seed);
        }
        if !self.floors_fit() {
            return Err(LineInvalid::FloorsDoNotFit);
        }
        Ok(())
    }

    /// The side of the allowance `track`'s floors are paid from: the pinned
    /// share for the pinned track, the rest of the allowance for the other.
    #[must_use]
    pub fn side_units(&self, track: Track) -> u64 {
        let pinned = self.pinned_units();
        if track == self.pinned_track {
            pinned
        } else {
            self.allowance_units.saturating_sub(pinned)
        }
    }

    /// Whether every seated family's floor fits its own side: the seats on
    /// a track times one floor stay within that track's side, so no floor
    /// is paid from the other side.
    #[must_use]
    pub fn floors_fit(&self) -> bool {
        [Track::Demand, Track::Interest].into_iter().all(|track| {
            let seats = self
                .families
                .iter()
                .filter(|seat| seat.track == track)
                .count() as u128;
            seats * u128::from(self.floor_units()) <= u128::from(self.side_units(track))
        })
    }

    /// The families the mint of period `index` divides over: those seated
    /// before it started. A family seated later has neither floor nor
    /// market ceiling until the next mint.
    #[must_use]
    pub fn seated_before(&self, start_ms: u64) -> Vec<&FamilySeat> {
        let mut seats: Vec<&FamilySeat> = self
            .families
            .iter()
            .filter(|seat| seat.admitted_at_ms < start_ms)
            .collect();
        seats.sort_by_key(|seat| seat.project);
        seats
    }

    /// Whether `seat`'s seed is still among the inputs of period `index`:
    /// from the first period minted after its seat, for `weight_periods`
    /// periods.
    #[must_use]
    pub fn seed_is_live(&self, seat: &FamilySeat, index: u32) -> bool {
        let Some(seed) = &seat.seed else {
            return false;
        };
        let first = self
            .period_index(seat.admitted_at_ms)
            .map_or(0, |admitted| u64::from(admitted) + 1);
        let index = u64::from(index);
        first <= index && index < first + u64::from(seed.weight_periods)
    }

    /// The window of period `index`: settled outcomes stamped in
    /// `[from, to)` are its inputs.
    #[must_use]
    pub fn window_of(&self, index: u32) -> Option<(u64, u64)> {
        let (start, _) = self.period_bounds(index)?;
        let span = self
            .period_secs
            .checked_mul(1_000)?
            .checked_mul(u64::from(self.window_periods))?;
        Some((start.saturating_sub(span), start))
    }
}

/// sha256, lower hex, of the canonical bytes of `inputs`.
#[must_use]
pub fn inputs_digest(inputs: &[FamilyPayoff]) -> String {
    let bytes = serde_json::to_vec(inputs).expect("period inputs serialize");
    bytes_to_hex_lower(&Sha256::digest(bytes))
}

/// Mints the record of period `index` of `line`: the floors of the families
/// seated before it started, the pinned and market pools, and one table of
/// market ceilings per rule in force, each rule taking an equal share of the
/// market pool (the first takes the remainder). `tallies` holds what the
/// outcomes settled inside the window say, by family; a family it does not
/// name has none.
///
/// # Errors
///
/// [`MintError`]: the period does not fit the clock, or a rule in force is
/// not built.
pub fn mint_period(
    line: &GpuLine,
    index: u32,
    tallies: &BTreeMap<EntityId, SettledTally>,
    minted_at_ms: u64,
) -> Result<GpuLinePeriod, MintError> {
    let (start_ms, end_ms) = line
        .period_bounds(index)
        .ok_or(MintError::PeriodOutOfRange)?;
    let seats = line.seated_before(start_ms);
    let floor_units = line.floor_units();
    let floors: Vec<FamilyFloor> = seats
        .iter()
        .map(|seat| FamilyFloor {
            family: seat.project,
            track: seat.track,
            units: floor_units,
        })
        .collect();
    let inputs: Vec<FamilyPayoff> = seats
        .iter()
        .map(|seat| {
            let tally = tallies.get(&seat.project).copied().unwrap_or_default();
            FamilyPayoff {
                family: seat.project,
                track: seat.track,
                wins: tally.wins,
                losses: tally.losses,
                cost_secs: tally.cost_secs,
                invalid_secs: tally.invalid_secs,
                seed: line
                    .seed_is_live(seat, index)
                    .then(|| seat.seed.clone())
                    .flatten(),
            }
        })
        .collect();
    let pinned_units = line.pinned_units();
    let demand_units = line.allowance_units.saturating_sub(pinned_units);
    let other_floors: u64 = floors
        .iter()
        .filter(|floor| floor.track != line.pinned_track)
        .fold(0, |sum, floor| sum.saturating_add(floor.units));
    let market_pool = demand_units.saturating_sub(other_floors);
    let market_families: Vec<&FamilyPayoff> = inputs
        .iter()
        .filter(|input| {
            input.track != line.pinned_track || line.pinned_mode == PinnedMode::FloorPlusMarket
        })
        .collect();
    let rules = line.rules.len() as u64;
    let mut tables = Vec::with_capacity(line.rules.len());
    for (position, rule) in line.rules.iter().enumerate() {
        let share = market_pool / rules.max(1);
        let pool_units = if position == 0 {
            share + market_pool % rules.max(1)
        } else {
            share
        };
        let ceilings = match rule.rule {
            AllowanceRule::PayoffShare => payoff_share(
                pool_units,
                &market_families,
                &inputs,
                line.first_rung_secs(),
                line.invalid_cost,
            ),
            AllowanceRule::PosteriorSampling | AllowanceRule::EvenSplit => {
                return Err(MintError::RuleNotBuilt(*rule));
            }
        };
        tables.push(AllowanceTable {
            rule: *rule,
            pool_units,
            ceilings,
        });
    }
    Ok(GpuLinePeriod {
        project: line.project,
        index,
        start_ms,
        end_ms,
        line_revision: line.revision,
        allowance_units: line.allowance_units,
        pinned_track: line.pinned_track,
        pinned_mode: line.pinned_mode,
        pinned_units,
        floor_units,
        floors,
        rung_caps_secs: line.rung_caps_secs.clone(),
        forecast_required: line.forecast_required,
        invalid_cost: line.invalid_cost,
        inputs_digest: inputs_digest(&inputs),
        inputs,
        tables,
        minted_at_ms,
    })
}

/// One family's cost under `invalid_cost`, its live seed included.
fn family_cost(input: &FamilyPayoff, invalid_cost: InvalidCost) -> u64 {
    let invalid = match invalid_cost {
        InvalidCost::CountsAsCost => input.invalid_secs,
        InvalidCost::CountsNowhere => 0,
    };
    let seed = input.seed.as_ref().map_or(0, |seed| seed.cost_secs);
    input.cost_secs.saturating_add(invalid).saturating_add(seed)
}

/// One family's wins, its live seed included.
fn family_wins(input: &FamilyPayoff) -> u64 {
    input
        .wins
        .saturating_add(input.seed.as_ref().map_or(0, |seed| seed.wins))
}

/// The fewest low bits every score drops so that `pool` times the highest
/// one fits a `u128`. All scores drop the same bits, so their ratios hold and
/// the ceilings they divide still sum to at most the pool.
fn score_shift(pool: u64, scores: &[(EntityId, u128)]) -> u32 {
    let top = scores.iter().map(|(_, score)| *score).max().unwrap_or(0);
    let mut shift = 0;
    while u128::from(pool).checked_mul(top >> shift).is_none() {
        shift += 1;
    }
    shift
}

/// `payoff_share@1` (section 4.3): confirmed promotions per GPU-second,
/// smoothed toward the lane's own base rate. The prior is lane-wide: the
/// line's whole cost per win over every seated family, or
/// [`NO_WIN_PRIOR_RUNGS`] rung-1 caps while the lane has no win, and at
/// least one second. Each market
/// family's ceiling is its share of the scores; the units rounding leaves go
/// to the highest score, then the lowest id. A family with no history scores
/// exactly the base rate.
#[must_use]
pub fn payoff_share(
    pool: u64,
    market_families: &[&FamilyPayoff],
    lane: &[FamilyPayoff],
    first_rung_secs: u64,
    invalid_cost: InvalidCost,
) -> Vec<(EntityId, u64)> {
    if market_families.is_empty() {
        return Vec::new();
    }
    let total_cost: u128 = lane
        .iter()
        .map(|input| u128::from(family_cost(input, invalid_cost)))
        .sum();
    let total_wins: u128 = lane
        .iter()
        .map(|input| u128::from(family_wins(input)))
        .sum();
    let prior_secs: u128 = if total_wins > 0 {
        total_cost / total_wins
    } else {
        u128::from(NO_WIN_PRIOR_RUNGS.saturating_mul(first_rung_secs))
    }
    .max(1);
    let scores: Vec<(EntityId, u128)> = market_families
        .iter()
        .map(|input| {
            let wins = u128::from(family_wins(input)) + 1;
            let divisor = u128::from(family_cost(input, invalid_cost)) + prior_secs;
            (input.family, wins * PAYOFF_SCORE_SCALE / divisor)
        })
        .collect();
    let shift = score_shift(pool, &scores);
    let scores: Vec<(EntityId, u128)> = scores
        .into_iter()
        .map(|(family, score)| (family, score >> shift))
        .collect();
    let sum: u128 = scores.iter().map(|(_, score)| *score).sum();
    let mut ceilings: Vec<(EntityId, u64)> = scores
        .iter()
        .map(|(family, score)| {
            let units = if sum == 0 {
                u128::from(pool) / scores.len() as u128
            } else {
                u128::from(pool) * score / sum
            };
            (*family, u64::try_from(units).unwrap_or(pool))
        })
        .collect();
    let given: u64 = ceilings.iter().map(|(_, units)| *units).sum();
    let leftover = pool.saturating_sub(given);
    if leftover > 0 {
        let top = scores
            .iter()
            .enumerate()
            .max_by(|(_, (left_id, left)), (_, (right_id, right))| {
                left.cmp(right).then(right_id.cmp(left_id))
            })
            .map(|(position, _)| position)
            .expect("at least one market family");
        ceilings[top].1 += leftover;
    }
    ceilings.sort_by_key(|(family, _)| *family);
    ceilings
}
