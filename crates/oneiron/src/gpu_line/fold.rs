//! The lane economy's shared shapes and its pure fold (design pass 32,
//! sections 3 and 4).
//!
//! A GPU line is the owner's policy for one lane project: a wallet of
//! `gpu_seconds` per period, a pinned share for one track, a floor per seated
//! family, rung caps and the allowance rules in force. Each period gets one
//! record, written once: its buckets and the market ceilings each rule gave.
//!
//! No balance is stored. A bucket's room is a fold over the period's spend
//! rows: the first-allowance holds of admitted arms and the draws of
//! reserved units, each unit charged as its job stands (live, settled or
//! void). [`plan_draws`] walks the draw order of section 4.2 over that room.
//! Everything here is pure and integer, so a replay gives the same answer.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::EntityId;
use crate::federation::WalletRef;
use crate::llm::run_admission::LeaseUnit;

/// The track a family's seat is on.
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
    /// The pinned track draws its floor and the pinned pool only, and the
    /// mint divides the market pool over the other track's families.
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

/// A family's history from the lane's own lab ledger: a prior with an origin
/// and a weight, never an outcome (ARCH-0079). Box-lost units are not in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PayoffSeed {
    pub wins: u64,
    pub losses: u64,
    pub cost_secs: u64,
    /// How many periods the seed stays among the mint's inputs.
    pub weight_periods: u32,
    /// Where the numbers came from (a ledger path and digest, say).
    pub origin: String,
}

/// One family's seat on a GPU line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FamilySeat {
    /// The family: a child project of the lane.
    pub project: EntityId,
    pub track: Track,
    pub seed: Option<PayoffSeed>,
    pub admitted_by: EntityId,
    /// The vault's clock.
    pub admitted_at_ms: u64,
}

/// The owner's policy for one lane's GPU time. Key: id16 of the lane project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GpuLine {
    /// The lane.
    pub project: EntityId,
    /// `gpu_seconds`: one GPU held for one second.
    pub unit: LeaseUnit,
    /// The host wallet the line's allocation funds.
    pub wallet: WalletRef,
    /// The fleet's `--who` for this line.
    pub fleet_who: String,
    pub period_secs: u64,
    /// The start of period 0 (the vault's clock).
    pub period_anchor_ms: u64,
    /// The wallet's amount each period.
    pub allowance_units: u64,
    pub pinned_track: Track,
    /// The pinned share as (numerator, denominator).
    pub pinned_parts: (u32, u32),
    pub pinned_mode: PinnedMode,
    /// Rung-1 allowances a seated family gets each period before any
    /// payoff-driven spend.
    pub floor_arms: u32,
    /// The cap of each rung in seconds; `rung_caps_secs[0]` is rung 1.
    pub rung_caps_secs: Vec<u64>,
    pub forecast_required: bool,
    /// The rules the mint funds, in order. One entry: the starter; a second
    /// turns the comparison on and halves the market pool.
    pub rules: Vec<RuleRef>,
    pub invalid_cost: InvalidCost,
    /// Outcomes older than this many periods leave the mint's inputs.
    pub window_periods: u32,
    /// Hosts a unit may ask for.
    pub hosts: Vec<String>,
    pub families: Vec<FamilySeat>,
    pub set_by: Option<EntityId>,
    pub set_at_ms: u64,
    /// Bumped at every write; a period record names the revision it read.
    pub revision: u64,
}

impl GpuLine {
    /// The period that holds `now_ms`; `None` before period 0 starts or past
    /// the last period a `u32` names.
    #[must_use]
    pub fn period_index(&self, now_ms: u64) -> Option<u32> {
        let period_ms = self.period_secs.checked_mul(1_000).filter(|ms| *ms > 0)?;
        let since = now_ms.checked_sub(self.period_anchor_ms)?;
        u32::try_from(since / period_ms).ok()
    }

    /// The start and end of period `index`, end exclusive; `None` when they
    /// do not fit a `u64`.
    #[must_use]
    pub fn period_bounds(&self, index: u32) -> Option<(u64, u64)> {
        let period_ms = self.period_secs.checked_mul(1_000)?;
        let start = period_ms
            .checked_mul(u64::from(index))
            .and_then(|offset| self.period_anchor_ms.checked_add(offset))?;
        Some((start, start.checked_add(period_ms)?))
    }

    /// The seat of `family`, if it holds one.
    #[must_use]
    pub fn seat(&self, family: &EntityId) -> Option<&FamilySeat> {
        self.families.iter().find(|seat| seat.project == *family)
    }

    /// The rung-1 cap: the size of one first allowance and of one floor arm.
    #[must_use]
    pub fn first_rung_secs(&self) -> u64 {
        self.rung_caps_secs.first().copied().unwrap_or(0)
    }

    /// One seated family's floor each period.
    #[must_use]
    pub fn floor_units(&self) -> u64 {
        u64::from(self.floor_arms).saturating_mul(self.first_rung_secs())
    }

    /// The pinned share of the allowance, rounded down.
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
}

/// One family's floor in a period record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FamilyFloor {
    pub family: EntityId,
    pub track: Track,
    pub units: u64,
}

/// What every rule of a period read for one family: settled outcomes of its
/// closed rungs inside the window, and its live seed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FamilyPayoff {
    pub family: EntityId,
    pub track: Track,
    /// Settled outcomes with `success = true`.
    pub wins: u64,
    /// Settled outcomes with `success = false`.
    pub losses: u64,
    /// Seconds charged to the family's measurable closed rungs.
    pub cost_secs: u64,
    /// Seconds charged to its invalid rungs; the rule adds them to the cost
    /// as the record's `invalid_cost` says. Box-lost seconds are in no input.
    pub invalid_secs: u64,
    pub seed: Option<PayoffSeed>,
}

/// The market ceilings one rule gave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct AllowanceTable {
    pub rule: RuleRef,
    /// This rule's share of the market pool.
    pub pool_units: u64,
    /// One ceiling per family the rule divided over, by family id.
    pub ceilings: Vec<(EntityId, u64)>,
}

/// The mint's receipt for one period of one line, written once. Key: id16
/// of the lane project and the period index. Everything the fold needs is
/// here, so a change to the line takes effect at the next mint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GpuLinePeriod {
    pub project: EntityId,
    pub index: u32,
    pub start_ms: u64,
    /// Exclusive.
    pub end_ms: u64,
    pub line_revision: u64,
    pub allowance_units: u64,
    pub pinned_track: Track,
    pub pinned_mode: PinnedMode,
    pub pinned_units: u64,
    /// One family's floor this period; a family seated after the mint gets
    /// this floor at once (the wallet still caps the total).
    pub floor_units: u64,
    /// The floors of the families seated at the mint.
    pub floors: Vec<FamilyFloor>,
    pub invalid_cost: InvalidCost,
    pub inputs: Vec<FamilyPayoff>,
    /// sha256 (lower hex) of the canonical bytes of `inputs`.
    pub inputs_digest: String,
    /// One per rule in force, in the line's order.
    pub tables: Vec<AllowanceTable>,
    pub minted_at_ms: u64,
}

impl GpuLinePeriod {
    /// The pinned pool: the pinned share less the floors of the pinned
    /// track's families seated at the mint.
    #[must_use]
    pub fn pinned_pool_units(&self) -> u64 {
        let floors: u64 = self
            .floors
            .iter()
            .filter(|floor| floor.track == self.pinned_track)
            .map(|floor| floor.units)
            .sum();
        self.pinned_units.saturating_sub(floors)
    }

    /// The floor of `family` this period.
    #[must_use]
    pub fn floor_of(&self, family: &EntityId) -> u64 {
        self.floors
            .iter()
            .find(|floor| floor.family == *family)
            .map_or(self.floor_units, |floor| floor.units)
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

    /// Whether a family on `track` may draw a market ceiling.
    #[must_use]
    pub fn draws_market(&self, track: Track) -> bool {
        track != self.pinned_track || self.pinned_mode == PinnedMode::FloorPlusMarket
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
    /// The family's floor.
    Floor,
    /// The pinned pool (the pinned track only).
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

/// How much of a unit's draws count now (the charging rule of section 3.7).
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

/// Spend charged against each bucket of one period, and the rule each arm's
/// market draws fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeriodRoom {
    period: GpuLinePeriod,
    used: BTreeMap<Bucket, u64>,
    /// What each open arm's hold still has, by arm.
    hold_left: BTreeMap<EntityId, u64>,
    arm_rule: BTreeMap<EntityId, RuleRef>,
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
    /// Folds `rows` over `period`. Rows of other periods are skipped, so
    /// unused room never crosses a period boundary.
    #[must_use]
    pub fn fold(period: &GpuLinePeriod, rows: &[SpendRow]) -> Self {
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
        }
    }

    /// The period this room was folded over.
    #[must_use]
    pub fn period(&self) -> &GpuLinePeriod {
        &self.period
    }

    fn used(&self, bucket: Bucket) -> u64 {
        self.used.get(&bucket).copied().unwrap_or(0)
    }

    /// Room left in `bucket`.
    #[must_use]
    pub fn left(&self, bucket: Bucket) -> u64 {
        match bucket {
            Bucket::FirstAllowance { arm } => self.hold_left.get(&arm).copied().unwrap_or(0),
            Bucket::Floor { family } => self
                .period
                .floor_of(&family)
                .saturating_sub(self.used(bucket)),
            Bucket::Pinned => self
                .period
                .pinned_pool_units()
                .saturating_sub(self.used(bucket)),
            Bucket::Market { family, rule } => self
                .period
                .ceiling_of(&family, rule)
                .saturating_sub(self.used(bucket)),
        }
    }

    /// The rule `arm`'s market draws fixed this period, if it drew one.
    #[must_use]
    pub fn arm_rule(&self, arm: &EntityId) -> Option<RuleRef> {
        self.arm_rule.get(arm).copied()
    }

    /// The rule a new market draw of `arm` in `family` takes: the rule the
    /// arm already drew this period; else the only rule in force; else the
    /// one rule whose ceiling for the family has room; else, when several
    /// have room, the pick of the low bits of
    /// `blake3(line, period, arm)` among them (section 4.2). `None` when no
    /// rule is in force.
    #[must_use]
    pub fn market_rule(&self, arm: &EntityId, family: &EntityId) -> Option<RuleRef> {
        if let Some(rule) = self.arm_rule(arm) {
            return Some(rule);
        }
        let rules: Vec<RuleRef> = self.period.tables.iter().map(|table| table.rule).collect();
        let with_room: Vec<RuleRef> = rules
            .iter()
            .copied()
            .filter(|rule| {
                self.left(Bucket::Market {
                    family: *family,
                    rule: *rule,
                }) > 0
            })
            .collect();
        match with_room.len() {
            0 => rules.first().copied(),
            1 => Some(with_room[0]),
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
                Some(with_room[pick])
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
    /// The family's seat track.
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

/// The buckets an ask may draw, in order (section 4.2 as LE-1 = B reads it).
/// Rung 1 takes the arm's first-allowance hold, then the family's floor; a
/// first-allowance hold starts at the floor. Then the pinned track takes the
/// pinned pool, and its market ceiling only in `FloorPlusMarket` mode; the
/// other track takes its market ceiling. The rung cap binds before this and
/// the wallet after it; neither is checked here.
#[must_use]
pub fn draw_order(room: &PeriodRoom, ask: &DrawAsk) -> Vec<Bucket> {
    let mut order = Vec::with_capacity(4);
    match ask.purpose {
        DrawPurpose::Unit { rung: 1 } => {
            order.push(Bucket::FirstAllowance { arm: ask.arm });
            order.push(Bucket::Floor { family: ask.family });
        }
        DrawPurpose::FirstAllowanceHold => order.push(Bucket::Floor { family: ask.family }),
        DrawPurpose::Unit { .. } => {}
    }
    let period = room.period();
    if ask.track == period.pinned_track {
        order.push(Bucket::Pinned);
    }
    if period.draws_market(ask.track)
        && let Some(rule) = room.market_rule(&ask.arm, &ask.family)
    {
        order.push(Bucket::Market {
            family: ask.family,
            rule,
        });
    }
    order
}

/// The draws that cover `ask.units` in the order of [`draw_order`], each
/// bucket taken as far as its room goes. Draws of zero units are left out.
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
