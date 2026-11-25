//! The fold over one period's spend rows: what each bucket holds and has
//! left (design pass 32, section 4.2).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::types::{FamilySeat, GpuLinePeriod, RuleRef, Side, Track};
use crate::EntityId;

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

    /// The rule whose table a market draw of an arm in `cohort` takes: the
    /// only rule in force; with two rules in force, the arm's own cohort when
    /// this period has a table of it (section 4.4: the cohort is the arm's
    /// for life, and its market draws never take the other half, even when
    /// that half has room). `None`, so the draw takes no market: no rule is
    /// in force, or the arm has no cohort in a comparison (a family that
    /// graduated waits for the next mint) or a cohort this period has no
    /// table of. The pick reads no room.
    #[must_use]
    pub fn market_rule(&self, cohort: Option<RuleRef>) -> Option<RuleRef> {
        match self.period.tables.as_slice() {
            [only] => Some(only.rule),
            [_, _] => {
                cohort.filter(|rule| self.period.tables.iter().any(|table| table.rule == *rule))
            }
            _ => None,
        }
    }
}
