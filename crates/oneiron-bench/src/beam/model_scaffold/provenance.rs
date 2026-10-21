//! Resolved-pin family disclosures; uncertainty and in-family results stay out of the frontier.
use super::{ArmKind, ModelRunPlan};
use oneiron::ModelId;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub(in crate::beam) struct JudgeRelationship {
    pub(in crate::beam) arm: ArmKind,
    pub(in crate::beam) answerer: ModelId,
    pub(in crate::beam) answerer_family: Option<String>,
    pub(in crate::beam) judge: ModelId,
    pub(in crate::beam) judge_family: Option<String>,
    pub(in crate::beam) relationship: &'static str,
    pub(in crate::beam) disposition: &'static str,
}
impl JudgeRelationship {
    pub(super) fn is_independent(&self) -> bool {
        self.relationship == "out_of_family"
    }
    pub(super) fn is_in_family(&self) -> bool {
        matches!(self.relationship, "in_family" | "self_judged")
    }
}
pub(super) fn relationships(plan: &ModelRunPlan) -> Vec<JudgeRelationship> {
    let family = |pin: &ModelId| {
        plan.model_families
            .get(pin)
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
    };
    plan.answerers
        .iter()
        .map(|arm| {
            let answerer_family = family(&arm.model.model_id);
            let judge_family = family(&plan.judge.model.model_id);
            let relationship = if arm.model.model_id == plan.judge.model.model_id {
                "self_judged"
            } else {
                match (&answerer_family, &judge_family) {
                    (Some(a), Some(j)) if a == j => "in_family",
                    (Some(_), Some(_)) => "out_of_family",
                    _ => "unknown",
                }
            };
            JudgeRelationship {
                arm: arm.arm,
                answerer: arm.model.model_id.clone(),
                answerer_family,
                judge: plan.judge.model.model_id.clone(),
                judge_family,
                relationship,
                disposition: if relationship == "out_of_family" {
                    "independent_comparison"
                } else if relationship == "unknown" {
                    "non_comparable"
                } else {
                    "walled_appendix"
                },
            }
        })
        .collect()
}
