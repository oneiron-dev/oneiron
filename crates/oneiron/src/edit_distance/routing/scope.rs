//! Routing scope and rung types.

use super::version::model_version_token;
use crate::edit_distance::delta::MEASUREMENT_ENGINE_VERSION;
use crate::llm::ModelId;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The axis one aggregate is keyed on: a model generation, a kind of work, and
/// the measurement engine version its edit masses were measured under.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoutingScopeKey {
    /// `ModelStack` identity of the generation that drafted the proposals —
    /// see [`RoutingScopeKey::for_model`] for how a [`ModelId`] becomes one.
    pub model_version: String,
    /// The amendment scope the judgments were recorded in, which is the same
    /// string ED-03 keys its cost rows on.
    pub task_class: String,
    /// The measurement engine version (`engine_ver`) of the folded edit
    /// masses: two versions never share an aggregate (FIX 7822).
    pub measurement_version: String,
}

impl RoutingScopeKey {
    /// The scope for an already-resolved version token, under the version
    /// this engine measures with.
    #[must_use]
    pub fn new(model_version: impl Into<String>, task_class: impl Into<String>) -> Self {
        Self {
            model_version: model_version.into(),
            task_class: task_class.into(),
            measurement_version: MEASUREMENT_ENGINE_VERSION.to_owned(),
        }
    }

    /// This scope under another measurement version.
    #[must_use]
    pub fn measured_under(mut self, measurement_version: impl Into<String>) -> Self {
        self.measurement_version = measurement_version.into();
        self
    }

    /// The scope a given model would be read under.
    ///
    /// This is the one direction the consumer needs: a router holds a
    /// [`ModelId`] and wants what is known about it. The token is
    /// `stack:<id>` when a registered stack claims the model, and
    /// `model:<id>` when none does — two namespaces that cannot collide, so
    /// an unregistered model gets its own aggregate rather than quietly
    /// sharing one.
    #[must_use]
    pub fn for_model(model: &ModelId, task_class: impl Into<String>) -> Self {
        Self::new(model_version_token(model), task_class)
    }
}

/// How far a task class has climbed the rollout ladder.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RolloutRung {
    /// Compute and persist; reach nothing. The default for every scope.
    #[default]
    Shadow,
    /// Informational: visible on [`routing_data_bar`](crate::edit_distance::routing::routing_data_bar), still feeding nothing.
    DataBar,
    /// [`routing_weight_hint`](crate::edit_distance::routing::routing_weight_hint) answers for this task class.
    Graduated,
}

impl RolloutRung {
    /// The pinned on-disk token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::DataBar => "data_bar",
            Self::Graduated => "graduated",
        }
    }

    /// Parses a pinned on-disk token.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "shadow" => Some(Self::Shadow),
            "data_bar" => Some(Self::DataBar),
            "graduated" => Some(Self::Graduated),
            _ => None,
        }
    }
}

/// What routing is told about a scope — cost and outcome, inseparably.
///
/// Both fields are populated from the same aggregate in the same read, and no
/// door on this module hands out one alone. See the module header for why that
/// is a type and not a comment.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct WeightHint {
    /// This generation's mean edit mass against the observed floor and
    /// ceiling of the same task class: `0.0` at the floor (cheapest to
    /// land), `1.0` at the ceiling (dearest). A COST INPUT, never a ban.
    pub relative_edit_cost: f32,
    /// The share of this scope's amendments whose proposal was SOUND —
    /// amended for an external change or the decider's taste rather than
    /// because it was wrong. `1.0` means nothing this generation proposed was
    /// ever judged a defect.
    pub outcome_score: f32,
}

/// One row of the informational read surface.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingScopeStats {
    pub key: RoutingScopeKey,
    pub rung: RolloutRung,
    /// Judged amendments folded into this scope.
    pub runs: u64,
    /// The same pair [`routing_weight_hint`](crate::edit_distance::routing::routing_weight_hint) would return, shown here whether
    /// or not the scope has graduated.
    pub hint: WeightHint,
}
