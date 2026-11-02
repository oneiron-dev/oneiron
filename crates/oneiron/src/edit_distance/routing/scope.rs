//! Routing scope and rung types.

use std::collections::BTreeMap;

use crate::edit_distance::delta::MEASUREMENT_ENGINE_VERSION;
use crate::learning::{PriorOrigin, TypeRef};
use crate::llm::ModelId;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The axis one head is keyed on: an executor at revision, a kind of work, the
/// task type the runs were placed in, and the measurement engine version its
/// edit masses were measured under (FIX 7826).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RoutingScopeKey {
    /// Executor identity at revision (`provider/name@revision`) that drafted
    /// the proposals, as the run was stamped — or the unknown-executor key
    /// for receipts that carry no stamp (FIX 9812).
    pub executor: String,
    /// The amendment scope the judgments were recorded in, which is the same
    /// string ED-03 keys its cost rows on.
    pub task_class: String,
    /// The task type the runs were placed in; `None` when no task placed
    /// them.
    pub type_ref: Option<TypeRef>,
    /// The measurement engine version (`engine_ver`) of the folded edit
    /// masses: two versions never share an aggregate (FIX 7822).
    pub measurement_version: String,
}

impl RoutingScopeKey {
    /// The untyped scope for an executor identity, under the version this
    /// engine measures with.
    #[must_use]
    pub fn new(executor: impl Into<String>, task_class: impl Into<String>) -> Self {
        Self {
            executor: executor.into(),
            task_class: task_class.into(),
            type_ref: None,
            measurement_version: MEASUREMENT_ENGINE_VERSION.to_owned(),
        }
    }

    /// This scope in task type `type_ref`.
    #[must_use]
    pub fn typed(mut self, type_ref: TypeRef) -> Self {
        self.type_ref = Some(type_ref);
        self
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
    /// [`ModelId`] and wants what is known about it. The model id is the
    /// executor identity at revision, so two models that share a stack, or one
    /// model at two revisions, keep two heads.
    #[must_use]
    pub fn for_model(model: &ModelId, task_class: impl Into<String>) -> Self {
        Self::new(model.as_str(), task_class)
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

/// Another executor's score a head reads beside too few own runs (ARCH-0056
/// §8, ARCH-0003 #prior-origins). Never own evidence: the carried runs stay
/// the other executor's.
#[derive(Debug, Clone, PartialEq)]
pub struct CarriedPrior {
    /// Always [`PriorOrigin::Carried`].
    pub origin: PriorOrigin,
    /// The executor whose head the value was carried from.
    pub from: String,
    /// That head's mean edit mass.
    pub value: f32,
    /// How many own runs the prior counts as.
    pub weight_runs: u64,
}

/// What routing is told about a head — cost and outcomes, inseparably.
///
/// Every field is populated from the same heads in the same read, and no door
/// on this module hands out the cost alone. See the module header for why that
/// is a type and not a comment.
#[derive(Debug, Clone, PartialEq)]
pub struct WeightHint {
    /// This head's mean edit mass against the observed floor and ceiling of
    /// the same task class and task type: `0.0` at the floor (cheapest to
    /// land), `1.0` at the ceiling (dearest). A COST INPUT, never a ban.
    /// `None` when the task type holds no range to compare against.
    pub relative_edit_cost: Option<f32>,
    /// The mean edit mass the head reads at: its own runs, joined by the
    /// carried prior at the prior's weight while the head is UNTESTED.
    pub edit_cost: f32,
    /// Judged amendments folded into this head: its own runs.
    pub runs: u64,
    /// The carried prior, while the own runs are below its weight.
    pub prior: Option<CarriedPrior>,
    /// The UNTESTED display mark: own runs below the prior's weight; equality
    /// clears it.
    pub untested: bool,
    /// Own runs per anchored outcome of the TASK each worked, as the write
    /// that settled it recorded (`completed`, `failed`, ...). Paired with the
    /// cost, never blended into it. `None` when no own run has an anchor.
    pub outcomes: Option<BTreeMap<String, u64>>,
    /// The share of the judge's attributed weight labelled
    /// [`environment`](crate::skill_attribution::AttributionVerdict::Environment)
    /// or [`preference_shift`](crate::skill_attribution::AttributionVerdict::PreferenceShift):
    /// an explanation of the cost, never an outcome score. `None` with no own
    /// runs.
    pub sound_share: Option<f32>,
    /// Own runs drafted on the judge's own model.
    pub on_judge_model: u64,
}

/// One row of the informational read surface.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingScopeStats {
    pub key: RoutingScopeKey,
    pub rung: RolloutRung,
    /// The same hint [`routing_weight_hint`](crate::edit_distance::routing::routing_weight_hint) would return, shown here whether
    /// or not the scope has graduated.
    pub hint: WeightHint,
}
