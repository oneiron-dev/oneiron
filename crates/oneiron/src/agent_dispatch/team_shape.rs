//! The team-shape skill's engine half (ARCH-0079 #planner, OF-541): the
//! closed pattern vocabulary, the seeded shape catalog with its
//! `works well for` priors, and the payoff rows the planner card carries.
//!
//! The skill itself is a workflow skill (`skills/team-shape/SKILL.md`,
//! seeded into the hub like every bootstrap skill and revised by the loop
//! from receipts). This module is what the planner reads at spawn time: the
//! same lessons, as typed priors. Its first lesson is *solo first*: models
//! carry weak priors about collaboration and a naive team often loses to
//! one agent, so when one agent already succeeds often, adding agents tends
//! to hurt (RESEARCH-0366). Receipts then outweigh every prior here.

use serde::{Deserialize, Serialize};

use crate::llm::ModelId;

/// Hub name of the seeded team-shape workflow skill.
pub const TEAM_SHAPE_SKILL_NAME: &str = "team-shape";

/// The skill's lessons, in the order the SKILL.md teaches them. The planner
/// puts the ones that fired into the spawn receipt's `why`.
pub const TEAM_SHAPE_LESSONS: [&str; 6] = [
    "solo first: when one agent already succeeds often, adding agents tends to hurt",
    "a team must beat solo at equal budget, not at ten times the spend",
    "committee narrows ideas: strong for researching what exists, late on generative work",
    "vote judges between finished options; debate only on request",
    "market needs a referee signed before the work: a test, a holdout, a pinned judge",
    "width has no count cap; the budget is the cap, and the plan states it before launch",
];

/// Who decides (ARCH-0079 #patterns). `Solo` is the width-1 degenerate
/// shape the skill starts from; the rest are OF-540's skill patterns.
/// Whether a team converges on one answer or diverges into many is a
/// setting of the pattern, not a pattern of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoordinationPattern {
    Solo,
    CeoDecides,
    Committee,
    Vote,
    Market,
    Rotation,
}

impl CoordinationPattern {
    pub const ALL: [Self; 6] = [
        Self::Solo,
        Self::CeoDecides,
        Self::Committee,
        Self::Vote,
        Self::Market,
        Self::Rotation,
    ];

    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Solo => "solo",
            Self::CeoDecides => "ceo_decides",
            Self::Committee => "committee",
            Self::Vote => "vote",
            Self::Market => "market",
            Self::Rotation => "rotation",
        }
    }

    pub fn from_token(token: &str) -> crate::error::Result<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "solo" => Ok(Self::Solo),
            "ceo_decides" | "ceo" => Ok(Self::CeoDecides),
            "committee" | "council" => Ok(Self::Committee),
            "vote" => Ok(Self::Vote),
            "market" => Ok(Self::Market),
            "rotation" => Ok(Self::Rotation),
            _ => Err(super::widen_record::invalid("unknown coordination pattern")),
        }
    }

    /// Whether this pattern runs more than one agent by construction.
    #[must_use]
    pub const fn is_team(self) -> bool {
        !matches!(self, Self::Solo)
    }

    /// The smallest width at which the pattern means anything.
    #[must_use]
    pub const fn min_width(self) -> u32 {
        match self {
            Self::Solo => 1,
            Self::CeoDecides => 2,
            Self::Committee | Self::Rotation => 3,
            Self::Vote => 3,
            Self::Market => 2,
        }
    }
}

/// One seeded shape: a pattern at a starting width, the plain
/// `works well for` line the planner reads as its prior for matching task
/// types, and the prior success rate the research seeds it with. Receipts
/// outweigh the prior like any prior (ARCH-0079 #works-well-for).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SeededShape {
    pub pattern: CoordinationPattern,
    pub width: u32,
    pub works_well_for: &'static str,
    pub prior_success_rate: f64,
    /// Prior weight, counted in runs (ARCH-0079 #seed-pin).
    pub prior_runs: f64,
}

/// The shipped shape catalog, solo first.
pub const SEEDED_SHAPES: [SeededShape; 6] = [
    SeededShape {
        pattern: CoordinationPattern::Solo,
        width: 1,
        works_well_for: "for most tasks, one agent with a clear brief usually works",
        prior_success_rate: 0.7,
        prior_runs: 4.0,
    },
    SeededShape {
        pattern: CoordinationPattern::CeoDecides,
        width: 3,
        works_well_for: "for work with independent advice streams, one decider after advice usually works",
        prior_success_rate: 0.62,
        prior_runs: 2.0,
    },
    SeededShape {
        pattern: CoordinationPattern::Committee,
        width: 4,
        works_well_for: "for researching what exists and refining, a committee with a chair usually works; it is late on generative work",
        prior_success_rate: 0.6,
        prior_runs: 2.0,
    },
    SeededShape {
        pattern: CoordinationPattern::Vote,
        width: 5,
        works_well_for: "for judging between finished options, a vote usually works",
        prior_success_rate: 0.58,
        prior_runs: 2.0,
    },
    SeededShape {
        pattern: CoordinationPattern::Market,
        width: 8,
        works_well_for: "for checkable work at width with a referee signed first, a market ladder usually works",
        prior_success_rate: 0.55,
        prior_runs: 2.0,
    },
    SeededShape {
        pattern: CoordinationPattern::Rotation,
        width: 3,
        works_well_for: "for reframing and open questions, rotation may work; it starts untested",
        prior_success_rate: 0.5,
        prior_runs: 0.5,
    },
];

/// The seeded shape for a pattern.
#[must_use]
pub fn seeded_shape(pattern: CoordinationPattern) -> &'static SeededShape {
    SEEDED_SHAPES
        .iter()
        .find(|shape| shape.pattern == pattern)
        .unwrap_or(&SEEDED_SHAPES[0])
}

/// One payoff-table row (ARCH-0079 #scoring): what team receipts measured
/// for one pattern at one width on one model, keyed by task type. The
/// projector that folds receipts into rows is OF-542's; the planner only
/// reads rows.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PayoffRow {
    /// ONE TASK TYPE stamp (OF-543); `None` is the root (unsure) type.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_type: Option<String>,
    pub pattern: CoordinationPattern,
    pub width: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelId>,
    pub runs: u32,
    pub successes: u32,
    /// Mean whole-spawn spend per run, in lease units.
    pub mean_cost_units: u64,
}

impl PayoffRow {
    /// Measured success rate blended with the shape's seeded prior, so a
    /// cell with no own runs reads its prior and own runs outweigh it fast.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let seed = seeded_shape(self.pattern);
        let prior_successes = seed.prior_success_rate * seed.prior_runs;
        (f64::from(self.successes) + prior_successes) / (f64::from(self.runs) + seed.prior_runs)
    }

    /// Expected spend for one more run of this row, in lease units.
    #[must_use]
    pub const fn expected_cost_units(&self) -> u64 {
        self.mean_cost_units
    }
}

/// The planner card (ARCH-0079 #planner): the payoff rows for this task
/// type, read at spawn. An empty card is a cold vault: every shape reads
/// its seeded prior and solo wins by construction.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PlannerCard {
    /// The task type these rows are keyed by; `None` is the root card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_type: Option<String>,
    #[serde(default)]
    pub rows: Vec<PayoffRow>,
}

impl PlannerCard {
    #[must_use]
    pub fn root(rows: Vec<PayoffRow>) -> Self {
        Self {
            task_type: None,
            rows,
        }
    }

    /// Rows for one pattern, widest evidence first.
    pub fn rows_for(&self, pattern: CoordinationPattern) -> Vec<&PayoffRow> {
        let mut rows: Vec<&PayoffRow> = self
            .rows
            .iter()
            .filter(|row| row.pattern == pattern)
            .collect();
        rows.sort_by_key(|row| std::cmp::Reverse(row.runs));
        rows
    }

    /// The best-measured success rate for a pattern on this card, or the
    /// seeded prior when the card has no row for it.
    #[must_use]
    pub fn success_rate(&self, pattern: CoordinationPattern, model: Option<&ModelId>) -> f64 {
        let best = self
            .rows
            .iter()
            .filter(|row| row.pattern == pattern)
            .filter(|row| model.is_none() || row.model.as_ref() == model || row.model.is_none())
            .map(PayoffRow::success_rate)
            .fold(f64::NEG_INFINITY, f64::max);
        if best.is_finite() {
            best
        } else {
            seeded_shape(pattern).prior_success_rate
        }
    }

    /// Own runs behind a pattern on this card (0 = prior only).
    #[must_use]
    pub fn runs_for(&self, pattern: CoordinationPattern) -> u32 {
        self.rows
            .iter()
            .filter(|row| row.pattern == pattern)
            .map(|row| row.runs)
            .sum()
    }
}

/// A concrete team shape a plan commits to: a pattern at a width.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShape {
    pub pattern: CoordinationPattern,
    pub width: u32,
}

impl TeamShape {
    pub const SOLO: Self = Self {
        pattern: CoordinationPattern::Solo,
        width: 1,
    };

    /// The seeded starting width for a pattern.
    #[must_use]
    pub fn seeded(pattern: CoordinationPattern) -> Self {
        Self {
            pattern,
            width: seeded_shape(pattern).width,
        }
    }

    /// Stable wire token, `pattern` or `pattern:width` past solo.
    #[must_use]
    pub fn token(&self) -> String {
        if self.pattern == CoordinationPattern::Solo {
            self.pattern.as_str().to_owned()
        } else {
            format!("{}:{}", self.pattern.as_str(), self.width)
        }
    }
}
