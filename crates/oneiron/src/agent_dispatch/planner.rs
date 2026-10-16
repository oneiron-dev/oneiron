//! The spawn planner (ARCH-0079 #planner, OF-541): turns a [`SpawnNeed`]
//! into a-launch-ready plan — which pattern, how wide, which model, what
//! budget — under a model ladder so cheap calls handle the easy cases.
//!
//! The planner reads the active model set and each model's description,
//! the budget, the spawn's need, care and notes, the planner card (payoff
//! rows for the task type, with seeds and pins in force) and the
//! team-shape skill, whose first lesson is *solo first*. A field the
//! spawn pinned is never overridden. The budget is an input to the plan,
//! never a refusal: the best shape that fits is fitted, with one line on
//! what more would buy.
//!
//! The deterministic selection here is the ladder's floor: it must always
//! be able to answer. When the host installs a [`crate::llm::decision::DecisionLadder`],
//! the rung the ladder selects may re-rank the top shapes through one
//! typed question ([`plan_spawn_routed`]); an abstention keeps the
//! deterministic pick. Each rung's executor is routed and scored like any
//! skill, so the ladder improves from receipts.
//!
//! When a run nears the end of its lease, [`AgentDispatcher::graceful_stop`]
//! asks every attempt to land (the queue's two-rung graceful cancel under
//! a budget warning), saves the partial results in a resumable
//! [`PartialResultHold`], and names the notice the owner gets. A
//! suspension is a hold, not a kill.

use serde::{Deserialize, Serialize};

use crate::attempt_queue::{
    AttemptId, AttemptQueue, CancelRequestOutcome, CancelStanding, LandingTrigger,
    RequestAttemptCancel,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning_setting::{
    PLANNER_BIG_PLAN_WIDTH, PLANNER_SOLO_MARGIN, PLANNER_SOLO_SUCCESS_FLOOR, setting_value,
};
use crate::llm::decision::{
    AnswerContract, DecisionAnswer, DecisionBand, DecisionBandPolicy, DecisionDial, DecisionRung,
    Reversibility,
};
use crate::llm::{ModelId, ReasoningEffort};
use crate::retrieval_depth::RetrievalDeadline;
use crate::side_table::{self, LegacyJson, SideTable};
use crate::vault::Vault;

use super::AgentDispatcher;
use super::team_shape::{
    CoordinationPattern, PlannerCard, TEAM_SHAPE_LESSONS, TeamShape, seeded_shape,
};
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

/// One model the planner may seat agents on: its id, the description the
/// router shows for it, and the measured per-agent expected spend (the
/// engine learns per-agent calibration from receipts; until a model has
/// runs, the host seeds this figure).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AvailableModel {
    pub model: ModelId,
    #[serde(default)]
    pub description: String,
    /// Expected whole-agent spend in lease units, at the plan's effort.
    pub expected_units_per_agent: u64,
}

/// The cost envelope every plan states before launch (OF-393, OF-532):
/// agent count, expected spend and the hard spend cap. The runtime
/// enforces only the cap, a BudgetGuard lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostEnvelope {
    pub agent_count: u32,
    pub expected_spend_units: u64,
    pub hard_cap_units: u64,
    pub per_agent_expected_units: u64,
}

impl CostEnvelope {
    fn for_shape(width: u32, per_agent: u64, hard_cap: u64) -> Self {
        Self {
            agent_count: width,
            expected_spend_units: per_agent.saturating_mul(u64::from(width)),
            hard_cap_units: hard_cap,
            per_agent_expected_units: per_agent,
        }
    }
}

/// One candidate shape quoted to the CEO before commit: expected payoff
/// and cost (ARCH-0079 #planner).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShapeQuote {
    pub shape: TeamShape,
    pub model: ModelId,
    pub expected_success_rate: f64,
    pub envelope: CostEnvelope,
    pub works_well_for: String,
}

/// The resolved plan: what will actually launch.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamPlan {
    pub shape: TeamShape,
    pub model: ModelId,
    pub care: CareLevel,
    pub effort: ReasoningEffort,
    pub envelope: CostEnvelope,
    pub rung: PlannerRung,
    /// True when the plan is the best shape found; false when the budget
    /// fitted it down (see `what_more_would_buy`).
    pub fitted_to_budget: bool,
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
    /// The runner-up shapes with payoff and cost, best first — the CEO's
    /// top-shapes view rides the same rows.
    pub alternatives: Vec<ShapeQuote>,
    pub why: Vec<String>,
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

/// The hard cap in force: the caller's budget, narrowed by a budget seed
/// or pin on the spawn — seeds and pins never widen a budget.
fn hard_cap(need: &SpawnNeed, budget_units: u64) -> u64 {
    match &need.budget_cap_units {
        Some(over) => budget_units.min(*over.value()),
        None => budget_units,
    }
}

/// The models a plan may seat: all available, or only the pinned one. A
/// pinned model the vault does not carry is refused, never substituted.
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
/// `weight_runs` against the card's own runs, so light seeds move fast and
/// heavy ones barely move.
fn seed_bonus<T: PartialEq>(over: &Option<SpawnOverride<T>>, candidate: &T, card_runs: u32) -> f64 {
    match over {
        Some(SpawnOverride::Seed { value, weight_runs }) if value == candidate => {
            weight_runs / (weight_runs + f64::from(card_runs) + 1.0)
        }
        _ => 0.0,
    }
}

/// Every candidate shape for this need, quoted and ranked. Ranking is
/// solo-first: candidates sort by expected success per unit spend, then
/// the solo-first gate holds solo unless a team clears it.
fn ranked_quotes(
    need: &SpawnNeed,
    card: &PlannerCard,
    models: &[AvailableModel],
    budget_units: u64,
) -> Result<Vec<ShapeQuote>> {
    if models.is_empty() {
        return Err(invalid("planner has no available models"));
    }
    let cap = hard_cap(need, budget_units);
    let seatable = seatable_models(need, models)?;
    let patterns: Vec<CoordinationPattern> = match need.pinned_pattern() {
        Some(pattern) => vec![pattern],
        None => CoordinationPattern::ALL.to_vec(),
    };
    let mut quotes = Vec::new();
    for pattern in patterns {
        for model in &seatable {
            let width = need
                .pinned_width()
                .unwrap_or_else(|| seeded_shape(pattern).width)
                .max(pattern.min_width());
            let shape = TeamShape { pattern, width };
            let card_rate = card.success_rate(pattern, Some(&model.model));
            let runs = card.runs_for(pattern);
            let bonus = seed_bonus(&need.pattern, &pattern, runs)
                + seed_bonus(&need.model, &model.model, runs)
                + seed_bonus(&need.width, &width, runs);
            quotes.push(ShapeQuote {
                shape,
                model: model.model.clone(),
                expected_success_rate: (card_rate + bonus * 0.1).clamp(0.0, 1.0),
                envelope: CostEnvelope::for_shape(width, model.expected_units_per_agent, cap),
                works_well_for: seeded_shape(pattern).works_well_for.to_owned(),
            });
        }
    }
    quotes.sort_by(|a, b| {
        payoff_density(b)
            .partial_cmp(&payoff_density(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.shape.width.cmp(&b.shape.width))
    });
    Ok(quotes)
}

/// Expected success per 1k lease units: how shapes compare at equal budget.
fn payoff_density(quote: &ShapeQuote) -> f64 {
    let spend = quote.envelope.expected_spend_units.max(1) as f64;
    quote.expected_success_rate * 1000.0 / spend
}

/// Quotes for the widest candidate a rung decision needs.
fn widest(quotes: &[ShapeQuote]) -> u32 {
    quotes
        .iter()
        .map(|quote| quote.shape.width)
        .max()
        .unwrap_or(1)
}

/// The CEO's top shapes: the best `n` candidate plans with expected payoff
/// and cost, before anything commits.
pub fn top_shapes(
    need: &SpawnNeed,
    card: &PlannerCard,
    models: &[AvailableModel],
    budget_units: u64,
    n: usize,
) -> Result<Vec<ShapeQuote>> {
    need.validate()?;
    let mut quotes = ranked_quotes(need, card, models, budget_units)?;
    quotes.truncate(n.max(1));
    Ok(quotes)
}

/// Plan one spawn deterministically: solo-first selection over the
/// planner card, pins honoured exactly, then fitted to the budget.
///
/// # Errors
///
/// A blank need, an invalid override, no available models, or a pinned
/// model the vault does not carry.
pub fn plan_spawn(
    need: &SpawnNeed,
    card: &PlannerCard,
    models: &[AvailableModel],
    budget_units: u64,
    thresholds: PlannerThresholds,
) -> Result<SpawnPlanReceipt> {
    need.validate()?;
    plan_from_quotes(
        need,
        ranked_quotes(need, card, models, budget_units)?,
        models,
        thresholds,
        None,
    )
}

/// Assemble the receipt from ranked quotes. `routed_pick` is the shape
/// token a ladder rung chose, when one ran; it may only pick among the
/// quotes, never invent a shape, and the solo-first gate still applies.
fn plan_from_quotes(
    need: &SpawnNeed,
    quotes: Vec<ShapeQuote>,
    models: &[AvailableModel],
    thresholds: PlannerThresholds,
    routed_pick: Option<&str>,
) -> Result<SpawnPlanReceipt> {
    let care = resolve_care(need);
    let rung = planner_rung_for(care, quotes.len(), widest(&quotes), thresholds);
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
    if let Some(token) = routed_pick
        && let Some(routed) = quotes.iter().find(|quote| quote.shape.token() == token)
    {
        chosen = routed.clone();
        why.push(format!("ladder rung picked {token}"));
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

    let (plan, fit_why) = fit_to_budget(chosen, models, care, rung);
    why.extend(fit_why);
    let alternatives = quotes
        .into_iter()
        .filter(|quote| quote.shape != plan.shape || quote.model != plan.model)
        .take(3)
        .collect();
    Ok(SpawnPlanReceipt {
        asked: need.clone(),
        plan,
        alternatives,
        why,
    })
}

/// Fit the best shape to the cap (ARCH-0079 #budget): shrink width one
/// agent at a time to the pattern's floor, then fall back to the cheapest
/// seatable model, then solo at width 1. Never a refusal — the narrowest
/// honest plan over a zero budget is solo with a zero cap, and the
/// receipt says what more would buy.
fn fit_to_budget(
    chosen: ShapeQuote,
    models: &[AvailableModel],
    care: CareLevel,
    rung: PlannerRung,
) -> (TeamPlan, Vec<String>) {
    let cap = chosen.envelope.hard_cap_units;
    let per_agent = chosen.envelope.per_agent_expected_units;
    let mut why = Vec::new();
    let base = |shape: TeamShape,
                model: ModelId,
                envelope: CostEnvelope,
                fitted: bool,
                more: Option<String>| TeamPlan {
        shape,
        model,
        care,
        effort: care.reasoning_effort(),
        envelope,
        rung,
        fitted_to_budget: fitted,
        what_more_would_buy: more,
    };
    if chosen.envelope.expected_spend_units <= cap {
        return (
            base(chosen.shape, chosen.model, chosen.envelope, false, None),
            why,
        );
    }
    let missing = chosen.envelope.expected_spend_units - cap;
    let more = Some(format!(
        "{} more lease units would buy {} on {} (expected success {:.2})",
        missing,
        chosen.shape.token(),
        chosen.model.as_str(),
        chosen.expected_success_rate
    ));
    // Shrink width toward the pattern floor.
    let floor = chosen.shape.pattern.min_width();
    let mut width = chosen.shape.width;
    while width > floor && per_agent.saturating_mul(u64::from(width)) > cap {
        width -= 1;
    }
    if per_agent.saturating_mul(u64::from(width)) <= cap {
        why.push(format!(
            "fitted {} to width {width} under the {cap}-unit cap",
            chosen.shape.pattern.as_str()
        ));
        let shape = TeamShape {
            pattern: chosen.shape.pattern,
            width,
        };
        let envelope = CostEnvelope::for_shape(width, per_agent, cap);
        return (base(shape, chosen.model, envelope, true, more), why);
    }
    // Cheapest seatable model at the pattern floor.
    if let Some(cheap) = models
        .iter()
        .min_by_key(|model| model.expected_units_per_agent)
        && cheap
            .expected_units_per_agent
            .saturating_mul(u64::from(floor))
            <= cap
    {
        why.push(format!(
            "fitted {} to {} at width {floor} under the {cap}-unit cap",
            chosen.shape.pattern.as_str(),
            cheap.model.as_str()
        ));
        let shape = TeamShape {
            pattern: chosen.shape.pattern,
            width: floor,
        };
        let envelope = CostEnvelope::for_shape(floor, cheap.expected_units_per_agent, cap);
        return (base(shape, cheap.model.clone(), envelope, true, more), why);
    }
    // Solo, width 1, cheapest model: the narrowest honest plan.
    let cheap = models
        .iter()
        .min_by_key(|model| model.expected_units_per_agent)
        .map(|model| (model.model.clone(), model.expected_units_per_agent))
        .unwrap_or((chosen.model.clone(), per_agent));
    why.push(format!(
        "budget fits only solo on {} under the {cap}-unit cap",
        cheap.0.as_str()
    ));
    let envelope = CostEnvelope::for_shape(1, cheap.1, cap);
    (base(TeamShape::SOLO, cheap.0, envelope, true, more), why)
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
/// quotes and ranks the shapes, then — when the care climbs past the
/// cheap classifier — the selected rung picks among the top quotes
/// through one typed question. Only the quoted shape tokens are options,
/// so an answer outside them, an abstention, or a failed run keeps the
/// deterministic pick.
///
/// # Errors
///
/// As [`plan_spawn`].
pub fn plan_spawn_routed(
    need: &SpawnNeed,
    card: &PlannerCard,
    models: &[AvailableModel],
    budget_units: u64,
    thresholds: PlannerThresholds,
    decisions: Option<&PlannerDecisions<'_>>,
) -> Result<SpawnPlanReceipt> {
    need.validate()?;
    let quotes = ranked_quotes(need, card, models, budget_units)?;
    let care = resolve_care(need);
    let rung = planner_rung_for(care, quotes.len(), widest(&quotes), thresholds);
    let routed = match (decisions, rung) {
        (Some(decisions), PlannerRung::SmallThinking | PlannerRung::Strong) => {
            routed_shape_pick(need, &quotes, decisions, rung)
        }
        _ => None,
    };
    plan_from_quotes(need, quotes, models, thresholds, routed.as_deref())
}

/// Ask the ladder to pick one quoted shape. `None` on abstention, an
/// out-of-vocabulary answer, or any ladder error: the floor's pick holds.
fn routed_shape_pick(
    need: &SpawnNeed,
    quotes: &[ShapeQuote],
    decisions: &PlannerDecisions<'_>,
    rung: PlannerRung,
) -> Option<String> {
    let options: Vec<String> = quotes
        .iter()
        .take(6)
        .map(|quote| quote.shape.token())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if options.len() < 2 {
        return None;
    }
    let question = crate::llm::decision::catalogue::PLANNER_SHAPE
        .question(
            &[need.task_type.as_deref().unwrap_or("root").as_bytes()],
            decisions.wording.clone(),
            AnswerContract::Choice { options },
        )
        .ok()?;
    let state = serde_json::json!({
        "need": need.need,
        "care": resolve_care(need).as_str(),
        "notes": need.notes,
        "lessons": TEAM_SHAPE_LESSONS,
        "shapes": quotes.iter().take(6).map(|quote| serde_json::json!({
            "shape": quote.shape.token(),
            "model": quote.model.as_str(),
            "expected_success_rate": quote.expected_success_rate,
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
        DecisionAnswer::Choice(token) => Some(token),
        _ => None,
    }
}

/// A run's saved partial state (ARCH-0079 #budget): the attempts that were
/// asked to wrap up, the partial results they handed over, and the plan
/// they were running. The hold is what a resume reads; the attempts
/// themselves sit in the queue's landing/paused states, never killed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PartialResultHold {
    /// The spawn (root) attempt this hold belongs to.
    pub root_attempt: AttemptId,
    pub attempts: Vec<AttemptId>,
    /// Partial result entity refs, lower-hex (the engine's wire spelling).
    #[serde(default)]
    pub partial_result_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<TeamPlan>,
    pub reason: String,
    pub held_at: u64,
}

/// What a graceful stop produced: per-attempt landing outcomes, the
/// durable hold, and the one-line notice for the owner.
#[derive(Debug, Clone, PartialEq)]
pub struct GracefulStop {
    pub hold: PartialResultHold,
    pub outcomes: Vec<(AttemptId, CancelRequestOutcome)>,
    pub notice: String,
}

/// Holds keyed by root attempt id.
const PLAN_HOLD: SideTable<AttemptId, PartialResultHold, LegacyJson> =
    SideTable::new(&side_table::AGENT_DISPATCH_PLAN_HOLD);

impl AgentDispatcher<'_> {
    /// Plan a spawn from this vault's learned settings, without a model
    /// ladder: the deterministic floor over the card the caller supplies.
    ///
    /// # Errors
    ///
    /// As [`plan_spawn`], plus a settings read failure.
    pub fn plan_spawn(
        &self,
        need: &SpawnNeed,
        card: &PlannerCard,
        models: &[AvailableModel],
        budget_units: u64,
    ) -> Result<SpawnPlanReceipt> {
        plan_spawn(
            need,
            card,
            models,
            budget_units,
            PlannerThresholds::from_vault(self.vault)?,
        )
    }

    /// Stop a run gracefully at the end of its lease: every attempt gets
    /// the wrap-up warning (a budget-warning landing request — finish the
    /// step, hand over what exists), the partial results are saved in a
    /// durable resumable hold, and the returned notice is the owner's.
    ///
    /// # Errors
    ///
    /// A queue or storage failure. An attempt with no standing reports its
    /// typed outcome in `outcomes` rather than failing the stop.
    pub fn graceful_stop(
        &self,
        root_attempt: AttemptId,
        attempts: &[AttemptId],
        plan: Option<TeamPlan>,
        partial_result_refs: Vec<EntityId>,
        actor: &str,
        standing: CancelStanding,
        reason: &str,
        now: u64,
    ) -> Result<GracefulStop> {
        if actor.trim().is_empty() {
            return Err(invalid("graceful stop actor is required"));
        }
        let queue = AttemptQueue::new(self.vault);
        let mut outcomes = Vec::with_capacity(attempts.len());
        for attempt in attempts {
            let outcome = queue.request_cancel(RequestAttemptCancel {
                id: *attempt,
                actor: actor.to_owned(),
                standing,
                trigger: LandingTrigger::BudgetWarning,
                reason: Some("wrap up: finish the step and hand over what exists".to_owned()),
                now,
            })?;
            outcomes.push((*attempt, outcome));
        }
        let hold = PartialResultHold {
            root_attempt,
            attempts: attempts.to_vec(),
            partial_result_refs: partial_result_refs.iter().map(|id| id.to_hex()).collect(),
            plan,
            reason: reason.to_owned(),
            held_at: now,
        };
        let mut wtxn = self.vault.store.env.write_txn()?;
        PLAN_HOLD.put(&self.vault.store, &mut wtxn, &root_attempt, &hold)?;
        wtxn.commit()?;
        let notice = format!(
            "run held with {} partial result(s) from {} agent(s); resume from the hold when ready",
            hold.partial_result_refs.len(),
            hold.attempts.len()
        );
        Ok(GracefulStop {
            hold,
            outcomes,
            notice,
        })
    }

    /// The saved hold for a spawn, if one was stopped gracefully.
    pub fn plan_hold(&self, root_attempt: AttemptId) -> Result<Option<PartialResultHold>> {
        let rtxn = self.vault.store.env.read_txn()?;
        PLAN_HOLD.get(&self.vault.store, &rtxn, &root_attempt)
    }

    /// Clear a hold once its run has resumed (or its owner gave it up).
    /// Clearing is bookkeeping only: it touches no attempt.
    pub fn clear_plan_hold(&self, root_attempt: AttemptId) -> Result<()> {
        let mut wtxn = self.vault.store.env.write_txn()?;
        PLAN_HOLD.delete(&self.vault.store, &mut wtxn, &root_attempt)?;
        wtxn.commit()?;
        Ok(())
    }
}
