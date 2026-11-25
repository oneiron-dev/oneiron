//! The lane economy's shared shapes and its pure fold (design pass 32,
//! sections 3 and 4).
//!
//! A GPU line is the owner's policy for one lane project: a wallet of
//! `gpu_seconds` per period, a pinned share for one track, a floor per seated
//! family, rung caps and the allowance rules in force. Each period gets one
//! record, written once: its pools and the market ceilings each rule gave,
//! under the budget policy it copied whole.
//!
//! No balance is stored. A pool's room is a fold over the period's spend
//! rows: the first-allowance holds of admitted arms and the draws of
//! reserved units, each unit charged as its job stands (live, settled or
//! void). [`plan_draws`] walks the line's draw order (section 4.2) over that
//! room. Everything here is pure and integer, so a replay gives the same
//! answer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::defaults;
use crate::EntityId;
use crate::federation::WalletRef;
use crate::llm::run_admission::LeaseUnit;

/// The kind of a family's seat.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Track {
    /// Work a client or the lane's goal asks for now.
    Demand,
    /// Work the owner funds for its own sake (looped transformers, memory and
    /// continual learning).
    Interest,
    /// A new idea (LE-6): one slot of the period's new-idea pool, at rung 1
    /// only, until it graduates or lapses.
    NewIdea,
}

/// The two sides of a period's allowance: the pinned share and the rest.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    /// The pinned share, which only the pinned track's seats are paid from.
    Pinned,
    /// The rest of the allowance: the other track's seats, the new-idea pool
    /// and the market pool.
    Unpinned,
}

/// What the pinned share lets the pinned track draw (LE-1).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum PinnedMode {
    /// The default (LE-1 = B): the pinned track's families also get market
    /// ceilings from the mint and draw on them once the pinned pool is spent.
    #[default]
    FloorPlusMarket,
    /// The mint divides the market pool over the other track's families
    /// only, so the pinned track has no market ceiling.
    Exclusive,
}

/// Whether the GPU seconds of an invalid rung count in a rule's cost (LE-5).
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum InvalidCost {
    /// The default (LE-5 = A): invalid time is cost in `payoff_share`'s
    /// divisor only; a family's losses never move for it.
    #[default]
    CountsAsCost,
    /// Invalid time counts in no input.
    CountsNowhere,
}

/// An allowance rule the mint can fund (LE-4).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AllowanceRule {
    /// Confirmed promotions per GPU-second, smoothed toward the lane's base
    /// rate (the starter).
    PayoffShare,
    /// One Beta sample per family per slot, from the BLAKE3 XOF.
    PosteriorSampling,
    /// The pool divided evenly over the families.
    EvenSplit,
}

impl AllowanceRule {
    /// The rule's stable name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PayoffShare => "payoff_share",
            Self::PosteriorSampling => "posterior_sampling",
            Self::EvenSplit => "even_split",
        }
    }
}

/// One version of one allowance rule, such as `payoff_share@1`.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
pub struct RuleRef {
    pub rule: AllowanceRule,
    pub version: u16,
}

impl RuleRef {
    /// The starter rule.
    pub const PAYOFF_SHARE_1: Self = Self {
        rule: AllowanceRule::PayoffShare,
        version: 1,
    };
    pub const POSTERIOR_SAMPLING_1: Self = Self {
        rule: AllowanceRule::PosteriorSampling,
        version: 1,
    };
    pub const EVEN_SPLIT_1: Self = Self {
        rule: AllowanceRule::EvenSplit,
        version: 1,
    };
}

impl std::fmt::Display for RuleRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}@{}", self.rule.as_str(), self.version)
    }
}

/// One pool in a track's draw order, relative to the arm and its family.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DrawStep {
    /// The arm's first-allowance hold; only at the head of a rung-1 order.
    FirstAllowance,
    /// The family's floor this period: its floor from the mint, a floor it
    /// took from its side's reserve, or a new idea's slot.
    Floor,
    /// The pinned pool.
    Pinned,
    /// The family's market ceiling in the arm's table.
    Market,
}

/// The pools an arm of one track draws, in order (section 4.2): one order
/// for rung 1 and one for every later rung. An ask the order does not cover
/// is refused; an empty order refuses every ask.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TrackDrawOrder {
    pub track: Track,
    pub first_rung: Vec<DrawStep>,
    pub later_rungs: Vec<DrawStep>,
}

/// The budget policy of a line: every setting an edit changes from the next
/// mint on (section 4.1). Each period record copies it whole. A field left
/// out takes the engine's neutral default (`gpu_line::defaults`); the
/// allowance and the rung caps have none, and a line that leaves them out is
/// refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct BudgetPolicy {
    /// Units a period.
    pub allowance_units: u64,
    /// The track the pinned share pays for.
    pub pinned_track: Track,
    /// The pinned share as (numerator, denominator).
    pub pinned_parts: (u32, u32),
    pub pinned_mode: PinnedMode,
    /// Rung-1 allowances one floor holds.
    pub floor_arms: u32,
    /// The cap of each rung in seconds; `rung_caps_secs[0]` is rung 1 and
    /// the last entry is the last rung.
    pub rung_caps_secs: Vec<u64>,
    /// Demand seats a lead may fill without the owner's proof (LE-7).
    pub seat_cap: u32,
    /// Seats on the pinned track a lead may fill without the owner's proof
    /// (pass 34, 3.1).
    pub pinned_seat_cap: u32,
    /// Floors held back per side for seats asked after the mint.
    pub seat_reserve_floors: u32,
    /// New-idea seats a period funds, one floor each (LE-6).
    pub new_idea_slots_per_period: u32,
    /// Periods a new idea is funded before it lapses, counting the one it
    /// was seated in.
    pub new_idea_periods: u32,
    /// Units a reviewer may book per rung under review (LE-8).
    pub review_check_secs: u64,
    /// A first-allowance hold no claim ever drew lapses after this long.
    pub hold_ttl_secs: u64,
    /// A unit claim whose job has not started this long after its
    /// reservation is released (design 5.2, custody): the next attempt or a
    /// late start finds it so, by a compare-and-set on its revision.
    pub claim_custody_secs: u64,
    /// Attempts of one family that may run at once; 0 is no cap (pass 34,
    /// 4.5). The reserve door reads it.
    pub max_running_per_family: u32,
    /// Whether a unit needs its runner's forecast before it reserves.
    pub forecast_required: bool,
    /// Forecasts are scored once this many arms have one.
    pub forecast_score_after: u32,
    /// The rules the mint funds, in order. One entry: the starter; a second
    /// turns the comparison on and halves the market pool.
    pub rules: Vec<RuleRef>,
    /// posterior_sampling@1's most slots per pool.
    pub posterior_max_slots: u32,
    /// posterior_sampling@1's most wins plus losses per family; more are scaled down together.
    pub posterior_max_evidence: u32,
    pub invalid_cost: InvalidCost,
    /// Outcomes older than this many periods leave the mint's inputs.
    pub window_periods: u32,
    /// The pools each track draws, in order: one entry per track.
    pub draw_orders: Vec<TrackDrawOrder>,
}

/// The engine's neutral defaults. The allowance is 0 and the rung caps are
/// empty: neither has an engine default, and `GpuLine::validate` refuses
/// both, so the owner or the lane's preset states them.
impl Default for BudgetPolicy {
    fn default() -> Self {
        Self {
            allowance_units: 0,
            pinned_track: defaults::PINNED_TRACK,
            pinned_parts: defaults::PINNED_PARTS,
            pinned_mode: PinnedMode::default(),
            floor_arms: defaults::FLOOR_ARMS,
            rung_caps_secs: Vec::new(),
            seat_cap: defaults::SEAT_CAP,
            pinned_seat_cap: defaults::PINNED_SEAT_CAP,
            seat_reserve_floors: defaults::SEAT_RESERVE_FLOORS,
            new_idea_slots_per_period: defaults::NEW_IDEA_SLOTS_PER_PERIOD,
            new_idea_periods: defaults::NEW_IDEA_PERIODS,
            review_check_secs: defaults::REVIEW_CHECK_SECS,
            hold_ttl_secs: defaults::HOLD_TTL_SECS,
            claim_custody_secs: defaults::CLAIM_CUSTODY_SECS,
            max_running_per_family: defaults::MAX_RUNNING_PER_FAMILY,
            forecast_required: defaults::FORECAST_REQUIRED,
            forecast_score_after: defaults::FORECAST_SCORE_AFTER,
            rules: defaults::RULES.to_vec(),
            posterior_max_slots: defaults::POSTERIOR_MAX_SLOTS,
            posterior_max_evidence: defaults::POSTERIOR_MAX_EVIDENCE,
            invalid_cost: InvalidCost::default(),
            window_periods: defaults::WINDOW_PERIODS,
            draw_orders: defaults::draw_orders(),
        }
    }
}

impl BudgetPolicy {
    /// The rung-1 cap: the size of one first allowance and of one floor arm.
    #[must_use]
    pub fn first_rung_secs(&self) -> u64 {
        self.rung_caps_secs.first().copied().unwrap_or(0)
    }

    /// One floor: `floor_arms` rung-1 allowances.
    #[must_use]
    pub fn floor_secs(&self) -> u128 {
        u128::from(self.floor_arms) * u128::from(self.first_rung_secs())
    }

    /// The pinned share of `allowance_units`, rounded down.
    #[must_use]
    pub fn pinned_units(&self) -> u64 {
        let (numerator, denominator) = self.pinned_parts;
        if denominator == 0 {
            return 0;
        }
        let units =
            u128::from(self.allowance_units) * u128::from(numerator) / u128::from(denominator);
        u64::try_from(units).unwrap_or(u64::MAX)
    }

    /// The side `track`'s seats are paid from.
    #[must_use]
    pub fn side_of(&self, track: Track) -> Side {
        if track == self.pinned_track {
            Side::Pinned
        } else {
            Side::Unpinned
        }
    }

    /// The draw order of `track`; `None` when the policy names none.
    #[must_use]
    pub fn draw_order_of(&self, track: Track) -> Option<&TrackDrawOrder> {
        self.draw_orders.iter().find(|order| order.track == track)
    }
}

/// The confirmed promote a new-idea seat graduated on (LE-6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Graduation {
    /// The kind the seat had before.
    pub from: Track,
    /// Who moved it; `None` after their erase.
    pub by: Option<EntityId>,
    pub at_ms: u64,
    /// The arm and rung of the confirmed promote.
    pub arm: EntityId,
    pub rung: u8,
}

/// One family's seat on a GPU line. A seat asked after its period began is
/// effective from the next mint; it may take a floor at once from its side's
/// reserve, or, for a new idea, a slot of the new-idea pool (`late_floor`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FamilySeat {
    /// The seat's own id: it survives a renamed or re-parented project.
    pub seat: EntityId,
    /// The family: a child project of the lane.
    pub project: EntityId,
    pub track: Track,
    /// The project's earlier seat, set by the engine: its history continues
    /// and it gets no second floor in a period.
    pub replaces: Option<EntityId>,
    pub graduated: Option<Graduation>,
    /// The first period the seat is no longer funded: a new idea with no
    /// graduation two periods after its first.
    pub lapsed_from_period: Option<u32>,
    /// The first period whose mint lists the seat.
    pub effective_from_period: u32,
    /// (period, units): the floor the seat took in the period it was asked,
    /// from that period's reserve or new-idea pool.
    pub late_floor: Option<(u32, u64)>,
    /// Who seated it; `None` after their erase.
    pub admitted_by: Option<EntityId>,
    /// The vault's clock.
    pub admitted_at_ms: u64,
}

impl FamilySeat {
    /// The kind the seat was asked as: its graduation's `from`, else its
    /// track. A late floor comes from this kind's pool.
    #[must_use]
    pub fn asked_track(&self) -> Track {
        self.graduated.as_ref().map_or(self.track, |grad| grad.from)
    }

    /// The first period the seat holds a floor in.
    #[must_use]
    pub fn first_funded_period(&self) -> u32 {
        self.late_floor
            .map_or(self.effective_from_period, |(period, _)| period)
    }

    /// The period a new idea that has not graduated lapses from: funded for
    /// `new_idea_periods` periods from its first (LE-6). `None` for every
    /// other seat.
    #[must_use]
    pub fn lapses_from(&self, new_idea_periods: u32) -> Option<u32> {
        (self.track == Track::NewIdea)
            .then(|| self.first_funded_period().saturating_add(new_idea_periods))
    }

    /// Whether the mint of period `index` lists the seat, new ideas being
    /// funded for `new_idea_periods` periods.
    #[must_use]
    pub fn funded_in(&self, index: u32, new_idea_periods: u32) -> bool {
        self.effective_from_period <= index
            && self
                .lapses_from(new_idea_periods)
                .is_none_or(|lapse| index < lapse)
            && self.lapsed_from_period.is_none_or(|lapse| index < lapse)
    }

    /// The late floor the seat took in period `index`, if any.
    #[must_use]
    pub fn late_floor_in(&self, index: u32) -> Option<u64> {
        self.late_floor
            .and_then(|(period, units)| (period == index).then_some(units))
    }
}

/// A role a Grant holds on a line (section 5.1).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum LineRole {
    Lead,
    Reviewer,
    Planner,
}

/// Why a time has no period on a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PeriodClockError {
    #[error("period_not_begun: the vault clock is before period 0 of this line")]
    NotBegun,
    #[error("period_out_of_range: the vault clock is past the last period this line can name")]
    OutOfRange,
}

/// The owner's policy for one lane's GPU time. Key: id16 of the lane project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GpuLine {
    /// The lane.
    pub project: EntityId,
    /// The unit the line counts in, which its offers' `cost_unit` equals:
    /// `gpu_seconds` is one GPU held for one second.
    pub unit: LeaseUnit,
    /// The host wallet the line's allocation funds.
    pub wallet: WalletRef,
    /// The offers this line manages; read at once on every use.
    pub offers: Vec<String>,
    /// The machines the line may run on; read at once on every use.
    pub machines: Vec<EntityId>,
    /// Grants that hold the lead role on this line.
    pub leads: Vec<EntityId>,
    /// Grants that hold the reviewer role on this line.
    pub reviewers: Vec<EntityId>,
    /// Grants that may seat a new idea and read the line (LE-6).
    pub planners: Vec<EntityId>,
    /// The schedule; fixed once a period is minted.
    pub period_secs: u64,
    /// The start of period 0 (the vault's clock).
    pub period_anchor_ms: u64,
    pub budget: BudgetPolicy,
    pub families: Vec<FamilySeat>,
    /// Who set the policy last; `None` after their erase.
    pub set_by: Option<EntityId>,
    pub set_at_ms: u64,
    /// Bumped at every write; a period record names the revision it read.
    pub revision: u64,
    /// The lane preset the policy was last set from, by its document's
    /// digest; `None` for a policy the owner stated whole (pass 34, 3.2). The
    /// values above are the full values in force either way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<crate::gpu_line::LinePresetRef>,
}

impl GpuLine {
    /// One period in milliseconds; `None` when it does not fit a `u64` or is
    /// zero.
    #[must_use]
    pub fn period_ms(&self) -> Option<u64> {
        self.period_secs.checked_mul(1_000).filter(|ms| *ms > 0)
    }

    /// The period that holds `now_ms` (section 4.1).
    ///
    /// # Errors
    ///
    /// [`PeriodClockError`]: `now_ms` is before the anchor, or past the last
    /// period a `u32` names.
    pub fn period_index(&self, now_ms: u64) -> Result<u32, PeriodClockError> {
        let period_ms = self.period_ms().ok_or(PeriodClockError::OutOfRange)?;
        let since = now_ms
            .checked_sub(self.period_anchor_ms)
            .ok_or(PeriodClockError::NotBegun)?;
        u32::try_from(since / period_ms).map_err(|_| PeriodClockError::OutOfRange)
    }

    /// The start and end of period `index`, end exclusive; `None` when they
    /// do not fit a `u64`.
    #[must_use]
    pub fn period_bounds(&self, index: u32) -> Option<(u64, u64)> {
        let period_ms = self.period_ms()?;
        let start = period_ms
            .checked_mul(u64::from(index))
            .and_then(|offset| self.period_anchor_ms.checked_add(offset))?;
        Some((start, start.checked_add(period_ms)?))
    }

    /// The live seat of `family`: the one that has not lapsed.
    #[must_use]
    pub fn seat(&self, family: &EntityId) -> Option<&FamilySeat> {
        self.families
            .iter()
            .find(|seat| seat.project == *family && seat.lapsed_from_period.is_none())
    }

    /// The newest seat `family` ever held on this line, lapsed or not.
    #[must_use]
    pub fn last_seat(&self, family: &EntityId) -> Option<&FamilySeat> {
        self.families
            .iter()
            .rev()
            .find(|seat| seat.project == *family)
    }

    /// Whether `grant` holds `role` on this line.
    #[must_use]
    pub fn holds_role(&self, grant: &EntityId, role: LineRole) -> bool {
        let grants = match role {
            LineRole::Lead => &self.leads,
            LineRole::Reviewer => &self.reviewers,
            LineRole::Planner => &self.planners,
        };
        grants.contains(grant)
    }

    /// Whether `grant` holds any role on this line.
    #[must_use]
    pub fn holds_any_role(&self, grant: &EntityId) -> bool {
        [LineRole::Lead, LineRole::Reviewer, LineRole::Planner]
            .into_iter()
            .any(|role| self.holds_role(grant, role))
    }
}

/// One family's floor in a period record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FamilyFloor {
    pub family: EntityId,
    pub track: Track,
    pub units: u64,
}

/// One seat a period funds, as the mint listed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SeatAtMint {
    pub seat: EntityId,
    pub family: EntityId,
    pub track: Track,
}

/// What every rule of a period read for one family: its outcomes and cost
/// inside the window (section 4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FamilyPayoff {
    pub family: EntityId,
    /// Rungs confirmed a win.
    pub wins: u64,
    /// Rungs closed a loss.
    pub losses: u64,
    /// Seconds charged to the family's claims, invalid rungs left out.
    pub cost_secs: u64,
    /// Seconds charged to its rungs closed invalid; a rule adds them to the
    /// cost as the record's `invalid_cost` says. Box-lost seconds are in no
    /// input.
    pub invalid_secs: u64,
}

/// The market ceilings one rule gave. `sum(ceilings) + unallocated` is
/// `pool_units`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AllowanceTable {
    pub rule: RuleRef,
    /// This rule's share of the market pool.
    pub pool_units: u64,
    /// One ceiling per family the rule divided over, by family id.
    pub ceilings: Vec<(EntityId, u64)>,
    /// What the rule gave nobody; it stays unspent.
    pub unallocated: u64,
}

/// The host allocation that funds one period (section 4.1): the record
/// names it and the installer installs exactly it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PeriodAllocation {
    pub wallet: WalletRef,
    /// Derived from the line; the generation names the period.
    pub id: String,
    pub generation: u64,
    pub units: u64,
}

/// The mint's record for one period of one line, written once. Key: id16
/// of the lane project and the period index. It carries the policy it was
/// minted under, so a replay needs no history of the line.
///
/// `allowance_units = sum(floors) + reserve.0 + reserve.1 + new_idea_pool +
/// pinned_pool + sum over tables (sum(ceilings) + unallocated) +
/// split_remainder`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GpuLinePeriod {
    pub project: EntityId,
    pub index: u32,
    pub start_ms: u64,
    /// Exclusive.
    pub end_ms: u64,
    /// The line revision the mint read.
    pub line_revision: u64,
    /// The budget policy in force this period.
    pub policy: BudgetPolicy,
    /// The seats this period funds, by family id.
    pub seats: Vec<SeatAtMint>,
    pub pinned_units: u64,
    pub unpinned_units: u64,
    /// The floors of the demand and interest seats the mint listed.
    pub floors: Vec<FamilyFloor>,
    /// One floor per new-idea slot, from the unpinned side.
    pub new_idea_pool: u64,
    /// (pinned side, unpinned side): floors held back for late seats.
    pub reserve: (u64, u64),
    pub pinned_pool: u64,
    pub market_pool: u64,
    pub inputs: Vec<FamilyPayoff>,
    /// Results written after this instant enter a later mint: the period's
    /// start.
    pub inputs_cutoff_ms: u64,
    /// One per rule in force, in the policy's order.
    pub tables: Vec<AllowanceTable>,
    /// The odd second when the market pool is halved.
    pub split_remainder: u64,
    /// sha256 of the cohort seed; `None` with one rule.
    pub cohort_seed_commit: Option<String>,
    /// No door returns it before `end_ms`.
    pub cohort_seed: Option<[u8; 32]>,
    pub allocation: PeriodAllocation,
    /// sha256 (lower hex) of every field but the cohort seed, its commit and
    /// `minted_at_ms`.
    pub economic_digest: String,
    /// Observational; outside the digest.
    pub minted_at_ms: u64,
}

impl GpuLinePeriod {
    /// One floor this period.
    #[must_use]
    pub fn floor_secs(&self) -> u64 {
        u64::try_from(self.policy.floor_secs()).unwrap_or(u64::MAX)
    }

    /// The reserve of `side`.
    #[must_use]
    pub fn reserve_of(&self, side: Side) -> u64 {
        match side {
            Side::Pinned => self.reserve.0,
            Side::Unpinned => self.reserve.1,
        }
    }

    /// The seat of `family` the mint listed, if any.
    #[must_use]
    pub fn seat_at_mint(&self, family: &EntityId) -> Option<&SeatAtMint> {
        self.seats.iter().find(|seat| seat.family == *family)
    }

    /// The floor `family` got from the mint: its floor, or a new idea's
    /// slot. Zero for a family the mint did not list.
    #[must_use]
    pub fn floor_of(&self, family: &EntityId) -> u64 {
        if let Some(floor) = self.floors.iter().find(|floor| floor.family == *family) {
            return floor.units;
        }
        match self.seat_at_mint(family) {
            Some(seat) if seat.track == Track::NewIdea => self.floor_secs(),
            _ => 0,
        }
    }

    /// The market ceiling of `family` under `rule`; zero when the rule is not
    /// in force or did not divide over the family.
    #[must_use]
    pub fn ceiling_of(&self, family: &EntityId, rule: RuleRef) -> u64 {
        self.tables
            .iter()
            .find(|table| table.rule == rule)
            .and_then(|table| table.ceilings.iter().find(|(id, _)| id == family))
            .map_or(0, |(_, units)| *units)
    }

    /// The new-idea slots the mint gave: one per new-idea seat it listed.
    #[must_use]
    pub fn new_idea_seats_at_mint(&self) -> usize {
        self.seats
            .iter()
            .filter(|seat| seat.track == Track::NewIdea)
            .count()
    }
}

/// Which bucket a draw takes from, relative to its arm and family.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum DrawSource {
    /// The arm's own first-allowance hold (rung 1 only).
    FirstAllowance,
    /// The family's floor this period (a new idea's slot included).
    Floor,
    /// The pinned pool.
    Pinned,
    /// The family's market ceiling under one rule.
    Market { rule: RuleRef },
}

/// Units taken from one bucket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct Draw {
    pub source: DrawSource,
    pub units: u64,
}

/// The first allowance an arm holds from its admission: one rung-1 cap, in
/// the period it was admitted. It lapses at that period's end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AllowanceHold {
    pub period: u32,
    pub units: u64,
    /// Where the hold sits, in draw order (never `FirstAllowance`).
    pub draws: Vec<Draw>,
}

/// How much of a unit's draws count now (the charging rule of section 4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitCharge {
    /// The job is live: every draw holds its full units.
    Live,
    /// The job settled this many seconds: the draws are charged in draw order
    /// until it is covered, and the rest is free again.
    Settled(u64),
    /// Nothing is charged: a released, refused, box-lost or never-booked
    /// unit.
    Void,
}

/// One row the fold reads. The caller builds it from the stored arm and
/// unit rows, joining each unit to its `GPU_JOB` for its charge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendRow {
    /// An arm's first-allowance hold. While the arm is open it holds its full
    /// units; once the arm closes it keeps only what the arm's units took
    /// from it.
    Hold {
        arm: EntityId,
        family: EntityId,
        hold: AllowanceHold,
        arm_open: bool,
    },
    /// One reserved unit's draws.
    Unit {
        arm: EntityId,
        family: EntityId,
        period: u32,
        draws: Vec<Draw>,
        charge: UnitCharge,
    },
}

/// A bucket of one period, named absolutely (for refusals and views).
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Bucket {
    FirstAllowance { arm: EntityId },
    Floor { family: EntityId },
    Pinned,
    Market { family: EntityId, rule: RuleRef },
}

impl Bucket {
    fn of(source: DrawSource, arm: EntityId, family: EntityId) -> Self {
        match source {
            DrawSource::FirstAllowance => Self::FirstAllowance { arm },
            DrawSource::Floor => Self::Floor { family },
            DrawSource::Pinned => Self::Pinned,
            DrawSource::Market { rule } => Self::Market { family, rule },
        }
    }
}

/// Spend charged against each bucket of one period, the floors seats took
/// after the mint, and the rule each arm's market draws fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodRoom {
    period: GpuLinePeriod,
    used: BTreeMap<Bucket, u64>,
    /// What each open arm's hold still has, by arm.
    hold_left: BTreeMap<EntityId, u64>,
    arm_rule: BTreeMap<EntityId, RuleRef>,
    /// Floors taken in this period after the mint, by family.
    late_floors: BTreeMap<EntityId, u64>,
    /// Of those, the floors each side's reserve gave.
    reserve_taken: BTreeMap<Side, u64>,
    /// Seats asked as new ideas that took a slot in this period after the
    /// mint.
    late_new_ideas: usize,
}

/// The units of `draws` charged when `charged` units of them count, in
/// draw order.
fn charged_in_order(draws: &[Draw], mut charged: u64) -> Vec<(DrawSource, u64)> {
    draws
        .iter()
        .map(|draw| {
            let take = draw.units.min(charged);
            charged -= take;
            (draw.source, take)
        })
        .collect()
}

fn unit_charged(draws: &[Draw], charge: UnitCharge) -> Vec<(DrawSource, u64)> {
    match charge {
        UnitCharge::Live => draws.iter().map(|draw| (draw.source, draw.units)).collect(),
        UnitCharge::Settled(secs) => charged_in_order(draws, secs),
        UnitCharge::Void => draws.iter().map(|draw| (draw.source, 0)).collect(),
    }
}

impl PeriodRoom {
    /// Folds `rows` over `period`, with the late floors `seats` took in it.
    /// Rows of other periods are skipped, so unused room never crosses a
    /// period boundary.
    #[must_use]
    pub fn fold(period: &GpuLinePeriod, seats: &[FamilySeat], rows: &[SpendRow]) -> Self {
        let mut late_floors: BTreeMap<EntityId, u64> = BTreeMap::new();
        let mut reserve_taken: BTreeMap<Side, u64> = BTreeMap::new();
        let mut late_new_ideas = 0;
        for seat in seats {
            let Some(units) = seat.late_floor_in(period.index) else {
                continue;
            };
            let floor = late_floors.entry(seat.project).or_default();
            *floor = floor.saturating_add(units);
            match seat.asked_track() {
                Track::NewIdea => late_new_ideas += 1,
                track => {
                    let taken = reserve_taken
                        .entry(period.policy.side_of(track))
                        .or_default();
                    *taken = taken.saturating_add(units);
                }
            }
        }
        let in_period = |row: &&SpendRow| match row {
            SpendRow::Hold { hold, .. } => hold.period == period.index,
            SpendRow::Unit { period: index, .. } => *index == period.index,
        };
        // An arm's first market draw fixes its rule: its hold comes before
        // its units.
        let mut arm_rule: BTreeMap<EntityId, RuleRef> = BTreeMap::new();
        let holds_first = rows
            .iter()
            .filter(in_period)
            .filter(|row| matches!(row, SpendRow::Hold { .. }))
            .chain(
                rows.iter()
                    .filter(in_period)
                    .filter(|row| matches!(row, SpendRow::Unit { .. })),
            );
        for row in holds_first {
            let (arm, draws) = match row {
                SpendRow::Hold { arm, hold, .. } => (arm, &hold.draws),
                SpendRow::Unit { arm, draws, .. } => (arm, draws),
            };
            if let Some(rule) = draws.iter().find_map(|draw| match draw.source {
                DrawSource::Market { rule } => Some(rule),
                _ => None,
            }) {
                arm_rule.entry(*arm).or_insert(rule);
            }
        }
        let mut used: BTreeMap<Bucket, u64> = BTreeMap::new();
        let mut taken_from_hold: BTreeMap<EntityId, u64> = BTreeMap::new();
        for row in rows.iter().filter(in_period) {
            let SpendRow::Unit {
                arm,
                family,
                draws,
                charge,
                ..
            } = row
            else {
                continue;
            };
            for (source, units) in unit_charged(draws, *charge) {
                if source == DrawSource::FirstAllowance {
                    *taken_from_hold.entry(*arm).or_default() += units;
                } else {
                    *used.entry(Bucket::of(source, *arm, *family)).or_default() += units;
                }
            }
        }
        let mut hold_left = BTreeMap::new();
        for row in rows.iter().filter(in_period) {
            let SpendRow::Hold {
                arm,
                family,
                hold,
                arm_open,
            } = row
            else {
                continue;
            };
            let taken = taken_from_hold.get(arm).copied().unwrap_or(0);
            let charged = if *arm_open {
                hold_left.insert(*arm, hold.units.saturating_sub(taken));
                hold.units
            } else {
                hold.units.min(taken)
            };
            for (source, units) in charged_in_order(&hold.draws, charged) {
                *used.entry(Bucket::of(source, *arm, *family)).or_default() += units;
            }
        }
        Self {
            period: period.clone(),
            used,
            hold_left,
            arm_rule,
            late_floors,
            reserve_taken,
            late_new_ideas,
        }
    }

    /// The period this room was folded over.
    #[must_use]
    pub fn period(&self) -> &GpuLinePeriod {
        &self.period
    }

    /// What `bucket` holds this period, before any spend. A first-allowance
    /// hold has no capacity of its own: its seconds sit in the pools it
    /// names.
    #[must_use]
    pub fn capacity(&self, bucket: Bucket) -> u64 {
        match bucket {
            Bucket::FirstAllowance { arm } => self.hold_left.get(&arm).copied().unwrap_or(0),
            Bucket::Floor { family } => self
                .period
                .floor_of(&family)
                .saturating_add(self.late_floors.get(&family).copied().unwrap_or(0)),
            Bucket::Pinned => self.period.pinned_pool,
            Bucket::Market { family, rule } => self.period.ceiling_of(&family, rule),
        }
    }

    /// What the period's holds and units charge `bucket` now: live holds and
    /// open units at their full units, ended ones at what they spent.
    #[must_use]
    pub fn used(&self, bucket: Bucket) -> u64 {
        match bucket {
            Bucket::FirstAllowance { .. } => 0,
            bucket => self.used.get(&bucket).copied().unwrap_or(0),
        }
    }

    /// Room left in `bucket`.
    #[must_use]
    pub fn left(&self, bucket: Bucket) -> u64 {
        self.capacity(bucket).saturating_sub(self.used(bucket))
    }

    /// The reserve `side` still holds for late seats.
    #[must_use]
    pub fn reserve_left(&self, side: Side) -> u64 {
        self.period
            .reserve_of(side)
            .saturating_sub(self.reserve_taken.get(&side).copied().unwrap_or(0))
    }

    /// New-idea slots this period has given: every seat that held one at any
    /// time in it, so a lapsed or graduated seat's slot is never given twice.
    #[must_use]
    pub fn new_idea_slots_taken(&self) -> usize {
        self.period.new_idea_seats_at_mint() + self.late_new_ideas
    }

    /// Whether `family` holds a floor this period, from the mint or taken
    /// after it.
    #[must_use]
    pub fn holds_floor(&self, family: &EntityId) -> bool {
        self.capacity(Bucket::Floor { family: *family }) > 0
    }

    /// The rule `arm`'s market draws fixed this period, if it drew one.
    #[must_use]
    pub fn arm_rule(&self, arm: &EntityId) -> Option<RuleRef> {
        self.arm_rule.get(arm).copied()
    }

    /// The rule a new market draw of `arm` takes: the rule the arm already
    /// drew this period; else the only rule in force; else the rule at the
    /// low bits of `blake3(line, period, arm)` modulo the rules in force.
    /// The pick never looks at room. `None` when no rule is in force.
    #[must_use]
    pub fn market_rule(&self, arm: &EntityId) -> Option<RuleRef> {
        if let Some(rule) = self.arm_rule(arm) {
            return Some(rule);
        }
        let rules: Vec<RuleRef> = self.period.tables.iter().map(|table| table.rule).collect();
        match rules.len() {
            0 => None,
            1 => Some(rules[0]),
            count => {
                let mut hasher = blake3::Hasher::new();
                hasher.update(b"oneiron.gpu_line.market_rule:v1");
                hasher.update(self.period.project.as_bytes());
                hasher.update(&self.period.index.to_le_bytes());
                hasher.update(arm.as_bytes());
                let digest = hasher.finalize();
                let mut low = [0u8; 8];
                low.copy_from_slice(&digest.as_bytes()[..8]);
                let pick = (u64::from_le_bytes(low) % count as u64) as usize;
                Some(rules[pick])
            }
        }
    }
}

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
