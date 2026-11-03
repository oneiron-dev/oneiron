use crate::team::spawn_override::SpawnOverride;
use serde::{Deserialize, Serialize};

/// How much a spawn cares (ARCH-0079 #spawn): the same five words vendors
/// use for reasoning effort, so a model reads `care: xhigh` without
/// explanation. On one call it sets reasoning effort; on a spawn the planner
/// reads it with the need and the budget.
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
pub enum CareLevel {
    Light,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
    Max,
}

impl CareLevel {
    /// Every care level, cheapest first.
    pub const ALL: [Self; 5] = [
        Self::Light,
        Self::Medium,
        Self::High,
        Self::XHigh,
        Self::Max,
    ];

    /// Stable wire token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Light => "light",
            Self::Medium => "medium",
            Self::High => "high",
            Self::XHigh => "xhigh",
            Self::Max => "max",
        }
    }

    /// Parse a wire token.
    pub fn from_token(token: &str) -> crate::error::Result<Self> {
        match token.trim().to_ascii_lowercase().as_str() {
            "light" => Ok(Self::Light),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            "xhigh" => Ok(Self::XHigh),
            "max" => Ok(Self::Max),
            _ => Err(super::widen_record::invalid("unknown care level")),
        }
    }

    /// Ladder position, 0 (light) to 4 (max).
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Light => 0,
            Self::Medium => 1,
            Self::High => 2,
            Self::XHigh => 3,
            Self::Max => 4,
        }
    }

    /// The reasoning effort one call at this care level runs. The effort
    /// ladder tops out at `xhigh`, so `max` care spends its extra care on
    /// team shape and budget instead.
    #[must_use]
    pub const fn reasoning_effort(self) -> crate::llm::ReasoningEffort {
        match self {
            Self::Light => crate::llm::ReasoningEffort::Low,
            Self::Medium => crate::llm::ReasoningEffort::Medium,
            Self::High => crate::llm::ReasoningEffort::High,
            Self::XHigh | Self::Max => crate::llm::ReasoningEffort::XHigh,
        }
    }
}

/// What a parent says when it spawns (ARCH-0079 #spawn): the required need,
/// separate from the prompt, plus optional care, notes and seeded or pinned
/// model, width, pattern and budget, and the type the engine placed once.
/// The planner routes on the need and fills in everything unset.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SpawnNeed {
    /// What the parent needs, in one or two lines. Required, non-blank.
    pub need: String,
    /// How much the parent cares; inferred from the need when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub care: Option<CareLevel>,
    /// Constraints and preferences (a model family, a time limit, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// The spawn's ONE TASK TYPE stamp (OF-543), placed once by the engine
    /// against the tree in force and the planner-card key. Required: an
    /// unsure placement is the root, never an absent type.
    pub type_ref: crate::task_type::TaskTypeRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<SpawnOverride<crate::llm::ModelId>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<SpawnOverride<u32>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<SpawnOverride<super::team_shape::CoordinationPattern>>,
    /// The whole spawn's budget, in lease units. A pin is the cap exactly;
    /// a seed is a prior worth its `weight_runs`, which the planner weighs
    /// against the launch's learned spend before it fits the plan (FIX
    /// 9561). Either is met with the caller's and parent's caps, never
    /// widens them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_cap_units: Option<SpawnOverride<u64>>,
    /// Leave the balance (`available_units`) out of the cost envelope the
    /// pattern run's model reads (FIX 9536). Off by default: the model reads
    /// the whole envelope. The host enforces, and the owner's receipts show,
    /// the full envelope either way.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub balance_free_prompt: bool,
}

impl SpawnNeed {
    #[must_use]
    pub fn new(need: impl Into<String>, type_ref: crate::task_type::TaskTypeRef) -> Self {
        Self {
            need: need.into(),
            care: None,
            notes: None,
            type_ref,
            model: None,
            width: None,
            pattern: None,
            budget_cap_units: None,
            balance_free_prompt: false,
        }
    }

    /// The door every planner entry runs first: the need is required and
    /// non-blank, the type stamp names a node, a width override names at
    /// least one agent, a budget override at least one unit, a seed weight
    /// is a positive finite run count, and the pins agree with each other.
    /// Inconsistent pins are invalid input: the planner never overrides a
    /// pin to reconcile them.
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.need.trim().is_empty() {
            return Err(super::widen_record::invalid("spawn need is required"));
        }
        if self.type_ref.node_id.is_empty() {
            return Err(super::widen_record::invalid(
                "spawn type stamp must name a node",
            ));
        }
        if let Some(width) = &self.width
            && *width.value() == 0
        {
            return Err(super::widen_record::invalid(
                "spawn width must be at least 1",
            ));
        }
        if let Some(budget) = &self.budget_cap_units
            && *budget.value() == 0
        {
            return Err(super::widen_record::invalid(
                "a spawn budget is more than zero units",
            ));
        }
        if let (Some(pattern), Some(width)) = (self.pinned_pattern(), self.pinned_width())
            && !pattern.admits_width(width)
        {
            return Err(super::widen_record::invalid(
                "pinned spawn width does not fit the pinned pattern",
            ));
        }
        let weights = [
            self.model.as_ref().map(SpawnOverride::weight_runs),
            self.width.as_ref().map(SpawnOverride::weight_runs),
            self.pattern.as_ref().map(SpawnOverride::weight_runs),
            self.budget_cap_units
                .as_ref()
                .map(SpawnOverride::weight_runs),
        ];
        if weights
            .into_iter()
            .flatten()
            .any(|w| w != f64::INFINITY && (!w.is_finite() || w <= 0.0))
        {
            return Err(super::widen_record::invalid(
                "spawn seed weight must be positive",
            ));
        }
        Ok(())
    }

    /// The pinned model, when the parent pinned one.
    #[must_use]
    pub fn pinned_model(&self) -> Option<&crate::llm::ModelId> {
        self.model
            .as_ref()
            .filter(|o| o.is_pin())
            .map(SpawnOverride::value)
    }

    /// The pinned width, when the parent pinned one.
    #[must_use]
    pub fn pinned_width(&self) -> Option<u32> {
        self.width
            .as_ref()
            .filter(|o| o.is_pin())
            .map(|o| *o.value())
    }

    /// The pinned pattern, when the parent pinned one.
    #[must_use]
    pub fn pinned_pattern(&self) -> Option<super::team_shape::CoordinationPattern> {
        self.pattern
            .as_ref()
            .filter(|o| o.is_pin())
            .map(|o| *o.value())
    }
}
