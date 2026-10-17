//! The spawn planner (ARCH-0079 #planner, OF-541): turns a [`SpawnNeed`]
//! into a launch-ready plan — which pattern, how wide, which seat, what
//! budget — under a model ladder so cheap calls handle the easy cases.
//!
//! The planner reads what the vault measured ([`PlannerEvidence`]): the
//! active seats with each model's description and its AGENT_DEF's
//! calibrated spend, the budget the launch runs under, solo's rate (the seat
//! AGENT_DEF's own reliability on the task type) and the planner card's read
//! of every bound pattern skill, with the payoff rows' anchored outcomes per
//! measured width. The live service ([`AgentDispatcher::plan_spawn_for_attempt`])
//! gathers it; this module is the algorithm. A field the spawn pinned is
//! never overridden, and pins that contradict each other are invalid input.
//! The budget is an input to the plan, never a refusal: the best shape that
//! fits is fitted, with one line on what more would buy, and a plan whose
//! pins leave nothing to fit keeps its pins and states the shortfall.
//!
//! The deterministic selection here is the ladder's floor: it must always
//! be able to answer. When the host installs a [`crate::llm::decision::DecisionLadder`],
//! the rung the care selects may re-rank the top candidates through one
//! typed question ([`plan_spawn_routed`]); an abstention keeps the
//! deterministic pick. The rung's workflow skill is loaded and its executor
//! recorded on the receipt, so the ladder is scored from receipts like any
//! skill.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning_setting::{
    PLANNER_BIG_PLAN_WIDTH, PLANNER_SOLO_MARGIN, PLANNER_SOLO_SUCCESS_FLOOR, setting_value,
};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionRung,
    ProviderPin, Reversibility,
};
use crate::llm::{ModelId, ReasoningEffort};
use crate::retrieval_depth::RetrievalDeadline;
use crate::team::PatternSkillRef;
use crate::vault::Vault;

use super::spend_calibration::ExpectedSpend;
use super::team_shape::{CoordinationPattern, TEAM_SHAPE_LESSONS, TeamShape};
use super::types::{CareLevel, SpawnNeed, SpawnOverride};
use super::widen_record::invalid;

/// One rung of the planner ladder. Cheap rungs handle the easy cases; the
/// strong rung is reserved for xhigh/max care or big plans.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlannerRung {
    /// A cheap classifier: the deterministic floor plus, at most, a local
    /// model sorting the need.
    CheapClassifier,
    /// A small thinking model weighs the top shapes.
    SmallThinking,
    /// A strong model plans (xhigh/max care, or a big plan).
    Strong,
}

impl PlannerRung {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CheapClassifier => "cheap_classifier",
            Self::SmallThinking => "small_thinking",
            Self::Strong => "strong",
        }
    }

    /// The decision-ladder rung this planner rung rides.
    #[must_use]
    pub const fn decision_rung(self) -> DecisionRung {
        match self {
            Self::CheapClassifier => DecisionRung::Local,
            Self::SmallThinking => DecisionRung::Escalation,
            Self::Strong => DecisionRung::Big,
        }
    }
}

/// One seat the planner may run agents on: a model, the description the
/// vault holds for it, and the AGENT_DEF that runs on it with that
/// AGENT_DEF's expected spend. Calibration is per AGENT_DEF and unit, learned
/// from settled launches; it is never a per-model figure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailableModel {
    pub model: ModelId,
    /// The vault's description lines for the model, strongest source first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub description: Vec<String>,
    /// The AGENT_DEF the seat runs: the calibration key.
    pub agent_def: EntityId,
    /// Expected whole-agent spend in the launch's unit, calibrated or the
    /// labelled prior.
    pub expected: ExpectedSpend,
}

/// The budget a plan is fitted to: the launch's binding hard cap and what
/// may be spent under it now, as the launch statement reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanBudget {
    /// `None`: the launch is unmetered by any lease tree.
    pub cap_units: Option<u64>,
    pub available_units: Option<u64>,
}

impl PlanBudget {
    /// No lease tree: nothing to fit to.
    pub const UNMETERED: Self = Self {
        cap_units: None,
        available_units: None,
    };

    /// The budget a stated launch runs under.
    #[must_use]
    pub fn from_launch(plan: &super::LaunchPlan) -> Self {
        plan.cap.as_ref().map_or(Self::UNMETERED, |cap| Self {
            cap_units: Some(cap.cap_units),
            available_units: Some(cap.available_units),
        })
    }

    /// The most the plan may spend now; `None` when unmetered.
    #[must_use]
    pub fn spendable(self) -> Option<u64> {
        match (self.cap_units, self.available_units) {
            (Some(cap), Some(available)) => Some(cap.min(available)),
            (cap, None) => cap,
            (None, available) => available,
        }
    }

    /// A budget seed or pin on the spawn only ever narrows the cap.
    fn narrowed(self, need: &SpawnNeed) -> Self {
        match &need.budget_cap_units {
            Some(over) => {
                let asked = *over.value();
                Self {
                    cap_units: Some(self.cap_units.map_or(asked, |cap| cap.min(asked))),
                    available_units: self.available_units,
                }
            }
            None => self,
        }
    }
}

/// The cost envelope every plan states before launch (OF-393, OF-532):
/// agent count, expected spend and the hard spend cap. The runtime
/// enforces only the cap, a BudgetGuard lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostEnvelope {
    pub agent_count: u32,
    pub expected_spend_units: u64,
    /// `None`: unmetered by any lease tree.
    pub hard_cap_units: Option<u64>,
    pub available_units: Option<u64>,
    /// One agent's expected spend and the evidence behind it.
    pub per_agent: ExpectedSpend,
}

impl CostEnvelope {
    fn for_shape(width: u32, per_agent: ExpectedSpend, budget: PlanBudget) -> Self {
        Self {
            agent_count: width,
            expected_spend_units: per_agent.units.saturating_mul(u64::from(width)),
            hard_cap_units: budget.cap_units,
            available_units: budget.available_units,
            per_agent,
        }
    }

    fn fits(&self, budget: PlanBudget) -> bool {
        budget
            .spendable()
            .is_none_or(|most| self.expected_spend_units <= most)
    }
}

/// One skill revision a plan read or ran.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillRevisionRef {
    pub skill: EntityId,
    pub version: String,
}

/// What the vault measured for one candidate on one seat: the posterior
/// mean in force, the candidate's own anchored runs (0 = prior only), and
/// the weight in runs the whole estimate carries (own runs plus its prior).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MeasuredRate {
    pub mean: f64,
    pub own_runs: f64,
    pub weight_runs: f64,
}

impl MeasuredRate {
    /// One width's anchored record, shrunk toward this estimate. Only
    /// anchored wins and losses count: an open team is neither.
    #[allow(clippy::cast_precision_loss)]
    fn pooled(self, wins: u64, losses: u64) -> Self {
        let (wins, losses) = (wins as f64, losses as f64);
        let weight = self.weight_runs.max(0.0);
        let total = wins + losses + weight;
        if total <= 0.0 {
            return self;
        }
        Self {
            mean: (wins + self.mean * weight) / total,
            own_runs: wins + losses,
            weight_runs: total,
        }
    }
}

/// One bound pattern skill the planner may run, as the planner card reads
/// it: the skill revision, the shape it teaches, its `works well for` line,
/// its estimate per seat model, and the anchored team outcomes per measured
/// width and seat model, `(wins, losses)`.
#[derive(Debug, Clone, PartialEq)]
pub struct PatternCandidate {
    pub skill: PatternSkillRef,
    pub pattern: CoordinationPattern,
    pub works_well_for: String,
    pub rates: BTreeMap<ModelId, MeasuredRate>,
    pub widths: BTreeMap<u32, BTreeMap<ModelId, (u64, u64)>>,
}

/// Everything one plan reads, gathered from the vault by the live service.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannerEvidence {
    /// One seat per model.
    pub models: Vec<AvailableModel>,
    /// Solo's rate per seat model: the seat AGENT_DEF's own reliability on
    /// the task type. Solo is a shape, never a pattern skill.
    pub solo: BTreeMap<ModelId, MeasuredRate>,
    pub patterns: Vec<PatternCandidate>,
    pub budget: PlanBudget,
}

/// One candidate quoted to the CEO before commit: expected payoff and cost
/// (ARCH-0079 #planner).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShapeQuote {
    /// The ladder's option id: shape, width, model and pattern skill, so no
    /// two candidates share one.
    pub candidate: String,
    pub shape: TeamShape,
    pub model: ModelId,
    pub agent_def: EntityId,
    /// The pattern skill revision a team runs; `None` for solo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_skill: Option<PatternSkillRef>,
    pub expected_success_rate: f64,
    /// Own anchored runs behind the estimate; 0 is prior only.
    pub own_runs: f64,
    pub envelope: CostEnvelope,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub works_well_for: Option<String>,
}

/// The resolved plan: what will actually launch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamPlan {
    pub shape: TeamShape,
    pub model: ModelId,
    /// The AGENT_DEF the launch seats.
    pub agent_def: EntityId,
    /// The pattern workflow skill a team runs; `None` for solo.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_skill: Option<PatternSkillRef>,
    pub care: CareLevel,
    pub effort: ReasoningEffort,
    pub envelope: CostEnvelope,
    pub rung: PlannerRung,
    /// True when the budget fitted the best shape down.
    pub fitted_to_budget: bool,
    /// The expected spend exceeds what may be spent now and the pins left
    /// nothing to fit. Stated, never refused: the lease refuses only spend
    /// beyond the cap.
    #[serde(default)]
    pub over_budget: bool,
    /// One line on what a bigger budget buys, when the best shape did not
    /// fit. The budget never refuses; it reports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub what_more_would_buy: Option<String>,
}

/// The spawn receipt: what was asked, what was resolved, and why.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpawnPlanReceipt {
    pub asked: SpawnNeed,
    pub plan: TeamPlan,
    /// The runner-up candidates with payoff and cost, best first — the
    /// CEO's top-shapes view rides the same rows.
    pub alternatives: Vec<ShapeQuote>,
    pub why: Vec<String>,
    /// The team-shape skill revision the plan read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_shape: Option<SkillRevisionRef>,
    /// The workflow skill the answering ladder rung ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rung_skill: Option<SkillRevisionRef>,
    /// The executors that read the rung's question, at revision.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rung_providers: Vec<ProviderPin>,
}

impl SpawnPlanReceipt {
    /// A receipt is whole and honest: its need validates, its shape is one
    /// the pattern can run, a team names its pattern skill, its envelope
    /// counts its agents, and no pinned field was overridden.
    ///
    /// # Errors
    ///
    /// [`crate::error::ArtifactError::InvalidAgentDispatchInput`] naming the
    /// broken rule.
    pub fn validate(&self) -> Result<()> {
        self.asked.validate()?;
        let plan = &self.plan;
        if !plan.shape.pattern.admits_width(plan.shape.width) {
            return Err(invalid("plan width does not fit its pattern"));
        }
        if plan.shape.pattern.is_team() != plan.pattern_skill.is_some() {
            return Err(invalid("a team plan runs a pattern skill; solo runs none"));
        }
        if plan.envelope.agent_count != plan.shape.width {
            return Err(invalid("plan envelope must count its agents"));
        }
        if self
            .asked
            .pinned_pattern()
            .is_some_and(|pattern| pattern != plan.shape.pattern)
            || self
                .asked
                .pinned_width()
                .is_some_and(|width| width != plan.shape.width)
            || self
                .asked
                .pinned_model()
                .is_some_and(|model| *model != plan.model)
        {
            return Err(invalid("a plan never overrides a pinned spawn field"));
        }
        Ok(())
    }

    /// The candidate id the resolved plan runs.
    #[must_use]
    pub fn candidate(&self) -> String {
        candidate_token(
            &self.plan.shape,
            &self.plan.model,
            self.plan.pattern_skill.as_ref(),
        )
    }
}

/// The planner thresholds in force: catalog seeds unless the owner seeded
/// or pinned the rows (a new knob is a catalog row, never a constant).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PlannerThresholds {
    /// Solo success rate at or above which the solo-first gate engages.
    pub solo_success_floor: f64,
    /// How far past solo a team must project to displace it under the gate.
    pub solo_margin: f64,
    /// Width at which a plan counts as big and climbs to the strong rung.
    pub big_plan_width: u32,
}

impl PlannerThresholds {
    #[must_use]
    pub fn seeded() -> Self {
        Self {
            solo_success_floor: PLANNER_SOLO_SUCCESS_FLOOR.seed,
            solo_margin: PLANNER_SOLO_MARGIN.seed,
            big_plan_width: PLANNER_BIG_PLAN_WIDTH.seed as u32,
        }
    }

    pub fn from_vault(vault: &Vault) -> Result<Self> {
        Ok(Self {
            solo_success_floor: setting_value(vault, &PLANNER_SOLO_SUCCESS_FLOOR)?,
            solo_margin: setting_value(vault, &PLANNER_SOLO_MARGIN)?,
            big_plan_width: setting_value(vault, &PLANNER_BIG_PLAN_WIDTH)?.max(1.0) as u32,
        })
    }
}

/// The care in force: the spawn's, else inferred from the need. Inference
/// is the cheap classifier rung's job; the deterministic floor reads
/// length and plain urgency words only.
#[must_use]
pub fn resolve_care(need: &SpawnNeed) -> CareLevel {
    if let Some(care) = need.care {
        return care;
    }
    let text = format!("{} {}", need.need, need.notes.as_deref().unwrap_or("")).to_lowercase();
    if [
        "critical",
        "must not fail",
        "production",
        "irreversible",
        "legal",
    ]
    .iter()
    .any(|word| text.contains(word))
    {
        CareLevel::XHigh
    } else if text.len() > 280 || text.contains("thorough") || text.contains("careful") {
        CareLevel::High
    } else if text.len() < 40 {
        CareLevel::Light
    } else {
        CareLevel::Medium
    }
}

/// Which ladder rung plans this spawn. Cheap first: the classifier takes
/// light/medium care with few candidates; high care or a crowded field
/// climbs to the small thinking model; xhigh/max care or a big plan goes
/// to the strong model.
#[must_use]
pub fn planner_rung_for(
    care: CareLevel,
    candidate_shapes: usize,
    widest_candidate: u32,
    thresholds: PlannerThresholds,
) -> PlannerRung {
    if care >= CareLevel::XHigh || widest_candidate >= thresholds.big_plan_width {
        PlannerRung::Strong
    } else if care >= CareLevel::High || candidate_shapes > 3 {
        PlannerRung::SmallThinking
    } else {
        PlannerRung::CheapClassifier
    }
}

/// The rung one set of ranked quotes plans at.
pub(super) fn planned_rung(
    need: &SpawnNeed,
    quotes: &[ShapeQuote],
    thresholds: PlannerThresholds,
) -> PlannerRung {
    planner_rung_for(resolve_care(need), quotes.len(), widest(quotes), thresholds)
}

/// The seats a plan may use: all, or only the pinned model's. A pinned
/// model no seat carries is refused, never substituted.
fn seatable_models<'a>(
    need: &SpawnNeed,
    models: &'a [AvailableModel],
) -> Result<Vec<&'a AvailableModel>> {
    match need.pinned_model() {
        Some(pinned) => models
            .iter()
            .find(|model| &model.model == pinned)
            .map(|model| vec![model])
            .ok_or_else(|| invalid("pinned spawn model is not available")),
        None => Ok(models.iter().collect()),
    }
}

/// Seed pull: a seeded (not pinned) value starts with a prior bonus worth
/// `weight_runs` against the candidate's own runs, so light seeds move fast
/// and heavy ones barely move.
fn seed_bonus<T: PartialEq>(over: &Option<SpawnOverride<T>>, candidate: &T, own_runs: f64) -> f64 {
    match over {
        Some(SpawnOverride::Seed { value, weight_runs }) if value == candidate => {
            weight_runs / (weight_runs + own_runs + 1.0)
        }
        _ => 0.0,
    }
}

/// A candidate's option id: `shape@model`, plus `#skill` for a team. Long
/// ids fall back to a digest, so every id fits a typed-choice option.
fn candidate_token(shape: &TeamShape, model: &ModelId, skill: Option<&PatternSkillRef>) -> String {
    let mut token = format!("{}@{}", shape.token(), model.as_str());
    if let Some(skill) = skill {
        token.push('#');
        token.push_str(&skill.skill.to_hex());
    }
    if token.len() > 256 {
        return format!(
            "candidate:{}",
            &blake3::hash(token.as_bytes()).to_hex().as_str()[..32]
        );
    }
    token
}

/// The widths a pattern candidate is quoted at: the pinned width alone, or
/// the pattern's floor, every width its payoff rows measured, and a seeded
/// width the pattern can run. No width is capped.
fn candidate_widths(need: &SpawnNeed, candidate: &PatternCandidate) -> BTreeSet<u32> {
    if let Some(width) = need.pinned_width() {
        return if candidate.pattern.admits_width(width) {
            BTreeSet::from([width])
        } else {
            BTreeSet::new()
        };
    }
    let mut widths: BTreeSet<u32> = candidate
        .widths
        .keys()
        .copied()
        .filter(|width| candidate.pattern.admits_width(*width))
        .collect();
    widths.insert(candidate.pattern.min_width());
    if let Some(SpawnOverride::Seed { value, .. }) = &need.width
        && candidate.pattern.admits_width(*value)
    {
        widths.insert(*value);
    }
    widths
}

fn quote(
    need: &SpawnNeed,
    shape: TeamShape,
    seat: &AvailableModel,
    skill: Option<&PatternSkillRef>,
    works_well_for: Option<&String>,
    rate: MeasuredRate,
    budget: PlanBudget,
) -> ShapeQuote {
    let runs = rate.own_runs;
    let bonus = seed_bonus(&need.pattern, &shape.pattern, runs)
        + seed_bonus(&need.model, &seat.model, runs)
        + seed_bonus(&need.width, &shape.width, runs);
    ShapeQuote {
        candidate: candidate_token(&shape, &seat.model, skill),
        shape,
        model: seat.model.clone(),
        agent_def: seat.agent_def,
        pattern_skill: skill.cloned(),
        expected_success_rate: (rate.mean + bonus * 0.1).clamp(0.0, 1.0),
        own_runs: runs,
        envelope: CostEnvelope::for_shape(shape.width, seat.expected, budget),
        works_well_for: works_well_for.cloned(),
    }
}

/// Every candidate for this need, quoted and ranked: solo on each seat, and
/// each bound pattern skill on each seat at each width it can run, filtered
/// by the pins. Ranking is by expected success per unit spend; the
/// solo-first gate applies when the plan is assembled.
pub(super) fn ranked_quotes(
    need: &SpawnNeed,
    evidence: &PlannerEvidence,
) -> Result<Vec<ShapeQuote>> {
    if evidence.models.is_empty() {
        return Err(invalid("planner has no available models"));
    }
    let budget = evidence.budget.narrowed(need);
    let seatable = seatable_models(need, &evidence.models)?;
    let pinned_pattern = need.pinned_pattern();
    let mut quotes = Vec::new();
    if pinned_pattern.is_none_or(|pattern| pattern == CoordinationPattern::Solo)
        && need.pinned_width().is_none_or(|width| width == 1)
    {
        for seat in &seatable {
            let rate = evidence
                .solo
                .get(&seat.model)
                .copied()
                .ok_or_else(|| invalid("planner evidence has no solo rate for a seat"))?;
            quotes.push(quote(need, TeamShape::SOLO, seat, None, None, rate, budget));
        }
    }
    for candidate in &evidence.patterns {
        if pinned_pattern.is_some_and(|pattern| pattern != candidate.pattern) {
            continue;
        }
        for seat in &seatable {
            let rate = candidate
                .rates
                .get(&seat.model)
                .copied()
                .ok_or_else(|| invalid("planner card has no read for a seat"))?;
            for width in candidate_widths(need, candidate) {
                let measured = candidate
                    .widths
                    .get(&width)
                    .and_then(|by_model| by_model.get(&seat.model))
                    .map_or(rate, |(wins, losses)| rate.pooled(*wins, *losses));
                quotes.push(quote(
                    need,
                    TeamShape {
                        pattern: candidate.pattern,
                        width,
                    },
                    seat,
                    Some(&candidate.skill),
                    Some(&candidate.works_well_for),
                    measured,
                    budget,
                ));
            }
        }
    }
    if quotes.is_empty() {
        return Err(invalid(
            "no bound pattern skill can run the pinned spawn shape",
        ));
    }
    quotes.sort_by(|a, b| {
        payoff_density(b)
            .total_cmp(&payoff_density(a))
            .then_with(|| a.shape.width.cmp(&b.shape.width))
            .then_with(|| a.candidate.cmp(&b.candidate))
    });
    Ok(quotes)
}

/// Expected success per 1k lease units: how shapes compare at equal budget.
#[allow(clippy::cast_precision_loss)]
fn payoff_density(quote: &ShapeQuote) -> f64 {
    let spend = quote.envelope.expected_spend_units.max(1) as f64;
    quote.expected_success_rate * 1000.0 / spend
}

/// The widest candidate a rung decision needs.
fn widest(quotes: &[ShapeQuote]) -> u32 {
    quotes
        .iter()
        .map(|quote| quote.shape.width)
        .max()
        .unwrap_or(1)
}

/// The CEO's top shapes: the best `n` candidate plans with expected payoff
/// and cost, before anything commits.
///
/// # Errors
///
/// As [`plan_spawn`].
pub fn top_shapes(
    need: &SpawnNeed,
    evidence: &PlannerEvidence,
    n: usize,
) -> Result<Vec<ShapeQuote>> {
    need.validate()?;
    let mut quotes = ranked_quotes(need, evidence)?;
    quotes.truncate(n.max(1));
    Ok(quotes)
}

/// Plan one spawn deterministically: solo-first selection over what the
/// vault measured, pins honoured exactly, then fitted to the budget.
///
/// # Errors
///
/// A blank need, an invalid or inconsistent override, no seats, a pinned
/// model no seat carries, or pins no bound pattern skill can run.
pub fn plan_spawn(
    need: &SpawnNeed,
    evidence: &PlannerEvidence,
    thresholds: PlannerThresholds,
) -> Result<SpawnPlanReceipt> {
    need.validate()?;
    plan_from_quotes(
        need,
        ranked_quotes(need, evidence)?,
        evidence,
        thresholds,
        None,
    )
}

/// A ladder rung's pick: the candidate id it chose and who read the question.
pub(super) struct RoutedPick {
    pub candidate: String,
    pub providers: Vec<ProviderPin>,
}

/// Assemble the receipt from ranked quotes. `routed` is the candidate a
/// ladder rung chose, when one ran; it may only pick among the quotes,
/// never invent a shape, and the solo-first gate still applies.
fn plan_from_quotes(
    need: &SpawnNeed,
    quotes: Vec<ShapeQuote>,
    evidence: &PlannerEvidence,
    thresholds: PlannerThresholds,
    routed: Option<&RoutedPick>,
) -> Result<SpawnPlanReceipt> {
    let care = resolve_care(need);
    let rung = planned_rung(need, &quotes, thresholds);
    let mut why = vec![format!(
        "planner rung {} for care {}",
        rung.as_str(),
        care.as_str()
    )];

    let solo = quotes
        .iter()
        .find(|quote| quote.shape.pattern == CoordinationPattern::Solo);
    let mut chosen = quotes
        .first()
        .ok_or_else(|| invalid("planner produced no candidate shapes"))?
        .clone();
    if let Some(pick) = routed
        && let Some(picked) = quotes
            .iter()
            .find(|quote| quote.candidate == pick.candidate)
    {
        chosen = picked.clone();
        why.push(format!("ladder rung picked {}", pick.candidate));
    }

    // Solo first: when solo already succeeds often, a team must project
    // past it by the margin to displace it. A pinned pattern or width is
    // the parent's call and skips the gate.
    let gate_holds = need.pinned_pattern().is_none() && need.pinned_width().is_none();
    if gate_holds
        && chosen.shape.pattern.is_team()
        && let Some(solo) = solo
        && solo.expected_success_rate >= thresholds.solo_success_floor
        && chosen.expected_success_rate < solo.expected_success_rate + thresholds.solo_margin
    {
        why.push(TEAM_SHAPE_LESSONS[0].to_owned());
        chosen = solo.clone();
    }

    if need.pinned_pattern().is_some()
        || need.pinned_width().is_some()
        || need.pinned_model().is_some()
    {
        why.push("pinned spawn fields honoured exactly".to_owned());
    }

    let (plan, fit_why) = fit_to_budget(&chosen, need, evidence, care, rung);
    why.extend(fit_why);
    let resolved = candidate_token(&plan.shape, &plan.model, plan.pattern_skill.as_ref());
    let alternatives = quotes
        .into_iter()
        .filter(|quote| quote.candidate != resolved)
        .take(3)
        .collect();
    let receipt = SpawnPlanReceipt {
        asked: need.clone(),
        plan,
        alternatives,
        why,
        team_shape: None,
        rung_skill: None,
        rung_providers: Vec::new(),
    };
    receipt.validate()?;
    Ok(receipt)
}

/// Fit the chosen shape to the budget (ARCH-0079 #budget), changing only
/// what the spawn left unpinned: narrow an unpinned width toward the
/// pattern's floor, then move an unpinned model to the cheapest seat, then
/// fall back to solo when neither pattern nor width is pinned. Never a
/// refusal: when the pins leave nothing that fits, the narrowest plan the
/// pins allow is kept and stated over budget, with what more would buy.
fn fit_to_budget(
    chosen: &ShapeQuote,
    need: &SpawnNeed,
    evidence: &PlannerEvidence,
    care: CareLevel,
    rung: PlannerRung,
) -> (TeamPlan, Vec<String>) {
    let budget = evidence.budget.narrowed(need);
    let mut why = Vec::new();
    let plan = |shape: TeamShape,
                seat: (&ModelId, EntityId, ExpectedSpend),
                skill: Option<PatternSkillRef>,
                fitted: bool,
                over: bool,
                more: Option<String>| TeamPlan {
        shape,
        model: seat.0.clone(),
        agent_def: seat.1,
        pattern_skill: skill,
        care,
        effort: care.reasoning_effort(),
        envelope: CostEnvelope::for_shape(shape.width, seat.2, budget),
        rung,
        fitted_to_budget: fitted,
        over_budget: over,
        what_more_would_buy: more,
    };
    let chosen_seat = (&chosen.model, chosen.agent_def, chosen.envelope.per_agent);
    if chosen.envelope.fits(budget) {
        return (
            plan(
                chosen.shape,
                chosen_seat,
                chosen.pattern_skill.clone(),
                false,
                false,
                None,
            ),
            why,
        );
    }
    let most = budget.spendable().unwrap_or(0);
    let fits = |width: u32, per_agent: ExpectedSpend| {
        CostEnvelope::for_shape(width, per_agent, budget).fits(budget)
    };
    let per_agent = chosen.envelope.per_agent;
    let dollars = ExpectedSpend {
        units: chosen.envelope.expected_spend_units,
        expected_usd_micros: per_agent
            .expected_usd_micros
            .and_then(|micros| micros.checked_mul(u64::from(chosen.shape.width))),
        ..per_agent
    }
    .dollar_clause();
    let more = Some(format!(
        "raise the available cap by {} lease units for {}{dollars} (expected success {:.2})",
        chosen.envelope.expected_spend_units.saturating_sub(most),
        chosen.candidate,
        chosen.expected_success_rate
    ));
    let width_free = need.pinned_width().is_none();
    let model_free = need.pinned_model().is_none();
    let pattern_free = need.pinned_pattern().is_none();
    let pattern = chosen.shape.pattern;

    // Narrow an unpinned width toward the pattern floor.
    let floor = pattern.min_width();
    let mut width = chosen.shape.width;
    if width_free {
        while width > floor && !fits(width, chosen.envelope.per_agent) {
            width -= 1;
        }
        if fits(width, chosen.envelope.per_agent) {
            why.push(format!(
                "fitted {} to width {width} under the {most}-unit budget",
                pattern.as_str()
            ));
            return (
                plan(
                    TeamShape { pattern, width },
                    chosen_seat,
                    chosen.pattern_skill.clone(),
                    true,
                    false,
                    more,
                ),
                why,
            );
        }
    }
    let cheapest = evidence
        .models
        .iter()
        .min_by(|a, b| {
            a.expected
                .units
                .cmp(&b.expected.units)
                .then_with(|| a.model.cmp(&b.model))
        })
        .map(|seat| (&seat.model, seat.agent_def, seat.expected));
    let seat = match cheapest {
        Some(cheap) if model_free => cheap,
        _ => chosen_seat,
    };
    // Move an unpinned model to the cheapest seat at that width.
    if model_free && seat.0 != chosen_seat.0 && fits(width, seat.2) {
        why.push(format!(
            "fitted {} to {} at width {width} under the {most}-unit budget",
            pattern.as_str(),
            seat.0.as_str()
        ));
        return (
            plan(
                TeamShape { pattern, width },
                seat,
                chosen.pattern_skill.clone(),
                true,
                false,
                more,
            ),
            why,
        );
    }
    // Solo, when neither the pattern nor the width is pinned.
    if pattern_free && width_free {
        let fits_solo = fits(1, seat.2);
        why.push(if fits_solo {
            format!(
                "budget fits only solo on {} under the {most}-unit budget",
                seat.0.as_str()
            )
        } else {
            format!(
                "solo on {} is the narrowest plan and still exceeds the {most}-unit budget",
                seat.0.as_str()
            )
        });
        return (
            plan(TeamShape::SOLO, seat, None, true, !fits_solo, more),
            why,
        );
    }
    // The pins leave nothing that fits: keep them and state the shortfall.
    why.push(format!(
        "pinned spawn fields keep the plan over the {most}-unit budget"
    ));
    let fitted = width != chosen.shape.width || seat.0 != chosen_seat.0;
    (
        plan(
            TeamShape { pattern, width },
            seat,
            chosen.pattern_skill.clone(),
            fitted,
            true,
            more,
        ),
        why,
    )
}

/// The host's planner-ladder decisions: its typed-decision ladder, the
/// principal the answer is for, its wording of the shape question, and the
/// call's clock. Mirrors the fan-out ask's shape: the engine bundles no
/// model and no prompt text.
pub struct PlannerDecisions<'a> {
    pub ladder: crate::llm::decision::DecisionLadder<'a>,
    pub principal: EntityId,
    pub bands: DecisionBandPolicy,
    pub wording: String,
    pub deadline: &'a RetrievalDeadline,
}

/// What the answering rung reads beside the quotes: the team-shape skill's
/// loaded content and the rung's own workflow skill, as their packs carry
/// them. Wording lives in the skills, not here.
#[derive(Debug, Clone, Copy, Default)]
pub struct PlannerQuestionContext<'a> {
    pub team_shape: Option<&'a str>,
    pub rung_skill: Option<&'a str>,
}

/// The dial a planner ask runs under: start at the rung the care selected,
/// never past the big model — a planner never queues a human to pick a
/// team shape; the deterministic floor answers instead.
fn planner_dial(rung: PlannerRung) -> DecisionDial {
    DecisionDial {
        first: rung.decision_rung(),
        ceiling: DecisionRung::Big,
        band: DecisionBand {
            low: 0.35,
            high: 0.65,
        },
    }
}

/// Plan one spawn with the model ladder engaged: the deterministic floor
/// quotes and ranks the candidates, then — when the care climbs past the
/// cheap classifier — the selected rung picks among the top quotes
/// through one typed question. Only the quoted candidate ids are options,
/// so an answer outside them, an abstention, or a failed run keeps the
/// deterministic pick.
///
/// # Errors
///
/// As [`plan_spawn`].
pub fn plan_spawn_routed(
    need: &SpawnNeed,
    evidence: &PlannerEvidence,
    thresholds: PlannerThresholds,
    decisions: Option<&PlannerDecisions<'_>>,
    context: PlannerQuestionContext<'_>,
) -> Result<SpawnPlanReceipt> {
    need.validate()?;
    let quotes = ranked_quotes(need, evidence)?;
    plan_ranked(need, quotes, evidence, thresholds, decisions, context)
}

/// [`plan_spawn_routed`] over quotes already ranked, so the live service
/// can load the rung's skill once it knows the rung.
pub(super) fn plan_ranked(
    need: &SpawnNeed,
    quotes: Vec<ShapeQuote>,
    evidence: &PlannerEvidence,
    thresholds: PlannerThresholds,
    decisions: Option<&PlannerDecisions<'_>>,
    context: PlannerQuestionContext<'_>,
) -> Result<SpawnPlanReceipt> {
    let rung = planned_rung(need, &quotes, thresholds);
    let routed = match (decisions, rung) {
        (Some(decisions), PlannerRung::SmallThinking | PlannerRung::Strong) => {
            routed_shape_pick(need, &quotes, evidence, decisions, rung, context)
        }
        _ => None,
    };
    let mut receipt = plan_from_quotes(need, quotes, evidence, thresholds, routed.as_ref())?;
    if let Some(pick) = routed {
        receipt.rung_providers = pick.providers;
    }
    Ok(receipt)
}

/// Ask the ladder to pick one quoted candidate. `None` on abstention, an
/// out-of-vocabulary answer, or any ladder error: the floor's pick holds.
fn routed_shape_pick(
    need: &SpawnNeed,
    quotes: &[ShapeQuote],
    evidence: &PlannerEvidence,
    decisions: &PlannerDecisions<'_>,
    rung: PlannerRung,
    context: PlannerQuestionContext<'_>,
) -> Option<RoutedPick> {
    let shown: Vec<&ShapeQuote> = quotes.iter().take(6).collect();
    let options: Vec<String> = shown
        .iter()
        .map(|quote| quote.candidate.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if options.len() < 2 {
        return None;
    }
    let type_wire = need.type_ref.wire_form();
    let question = crate::llm::decision::catalogue::PLANNER_SHAPE
        .question(
            &[type_wire.as_bytes()],
            decisions.wording.clone(),
            AnswerContract::Choice { options },
        )
        .ok()?;
    let state = serde_json::json!({
        "need": need.need,
        "care": resolve_care(need).as_str(),
        "notes": need.notes,
        "type_ref": type_wire,
        "lessons": TEAM_SHAPE_LESSONS,
        "team_shape": context.team_shape,
        "rung_skill": context.rung_skill,
        "models": evidence.models.iter().map(|seat| serde_json::json!({
            "model": seat.model.as_str(),
            "description": seat.description,
            "expected_units_per_agent": seat.expected.units,
            "spend_basis": seat.expected.basis,
        })).collect::<Vec<_>>(),
        "shapes": shown.iter().map(|quote| serde_json::json!({
            "candidate": quote.candidate,
            "shape": quote.shape.token(),
            "width": quote.shape.width,
            "model": quote.model.as_str(),
            "pattern_skill": quote.pattern_skill.as_ref().map(|skill| skill.skill.to_hex()),
            "expected_success_rate": quote.expected_success_rate,
            "own_runs": quote.own_runs,
            "expected_spend_units": quote.envelope.expected_spend_units,
            "works_well_for": quote.works_well_for,
        })).collect::<Vec<_>>(),
    });
    // Picking a shape starts agents, so a cut abstains to the floor.
    let decision = decisions
        .ladder
        .run(
            &question,
            decisions.principal,
            &[],
            &state,
            planner_dial(rung),
            &decisions.bands,
            Reversibility::OutboundEffect,
            decisions.deadline,
        )
        .ok()?;
    match decision.answer {
        DecisionAnswer::Choice(candidate) => Some(RoutedPick {
            candidate,
            providers: decision.receipt.providers,
        }),
        _ => None,
    }
}
