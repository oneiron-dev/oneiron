//! The plan the eval-authoring skill answers with, checked whole against its
//! inventory and applied in order: families for whole groups first, then
//! cases and their fixed-code labels, then each cut with its audit, then
//! retirements. A decision a door refuses is reported, never forced.
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::super::cohort::{CohortRetirement, MAX_REASON_BYTES};
use super::super::cut_audit::{AuditProvenance, prepare_cut_audit};
use super::super::{
    DerivationKind, EvalCaseDraft, EvalLabel, EvalSeat, FamilyPurpose, MAX_NAME_BYTES,
    MAX_REF_BYTES, invalid,
};
use super::{EvalAuthoringInventory, LineageReader, inventory_digest};
use crate::Vault;
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};

/// A purpose for one new source group, given before any case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyDecision {
    pub group: String,
    pub purpose: FamilyPurpose,
}

/// One candidate kept as a case, with the slice it was drawn for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseDecision {
    pub candidate: String,
    #[serde(default)]
    pub stratum: Option<String>,
}

/// One cohort to cut for a seat.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutDecision {
    pub seat: EvalSeat,
    pub from: u64,
    pub until: u64,
    pub rubric_revision: String,
    pub reference: bool,
}

/// Whether one cohort retires, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalCohortDecision {
    pub cohort: EntityId,
    pub retire: bool,
    #[serde(default)]
    pub reason: String,
}

/// The eval-authoring skill's answer for one inventory. The first decision
/// for an id stands; a later one for the same id is ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalAuthoringPlan {
    pub inventory_digest: String,
    #[serde(default)]
    pub families: Vec<FamilyDecision>,
    #[serde(default)]
    pub cases: Vec<CaseDecision>,
    #[serde(default)]
    pub cuts: Vec<CutDecision>,
    #[serde(default)]
    pub cohorts: Vec<EvalCohortDecision>,
}

/// One decision a door or the inventory did not let through.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EvalAuthoringSkip {
    /// The group, candidate, cut or cohort it named.
    pub item: String,
    pub reason: String,
}

/// What one applied plan did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EvalAuthoringReport {
    pub families_assigned: usize,
    pub families_extended: usize,
    pub cases_recorded: usize,
    pub cases_reused: usize,
    pub labels_added: usize,
    pub cohorts_cut: Vec<EntityId>,
    /// Cuts whose audit could not read every compared case's text.
    pub cuts_with_coverage_gaps: usize,
    pub cohorts_retired: Vec<EntityId>,
    pub cohorts_kept: usize,
    pub skipped: Vec<EvalAuthoringSkip>,
}

impl EvalAuthoringReport {
    fn skip(&mut self, item: impl Into<String>, reason: impl Into<String>) {
        self.skipped.push(EvalAuthoringSkip {
            item: item.into(),
            reason: reason.into(),
        });
    }
}

/// The reason an eval-set door refused, or the error when it was no refusal.
fn refusal(error: Error) -> Result<&'static str> {
    match error {
        Error::Artifact(ArtifactError::InvalidSkillBody(reason)) => Ok(reason),
        error => Err(error),
    }
}

/// Refuses a plan for another inventory, one naming what the inventory did
/// not hold, or one with a malformed field. Nothing is refused for how many
/// decisions it holds.
fn validate(plan: &EvalAuthoringPlan, inventory: &EvalAuthoringInventory) -> Result<()> {
    if plan.inventory_digest != inventory.inventory_digest
        || inventory_digest(inventory)? != inventory.inventory_digest
    {
        return Err(invalid("an eval-authoring plan is for another inventory"));
    }
    let groups: BTreeSet<&str> = inventory
        .groups
        .iter()
        .map(|group| group.id.as_str())
        .collect();
    let candidates: BTreeSet<&str> = inventory
        .candidates
        .iter()
        .map(|candidate| candidate.id.as_str())
        .collect();
    let seats: BTreeSet<&EvalSeat> = inventory.seats.iter().map(|seat| &seat.seat).collect();
    let cohorts: BTreeSet<EntityId> = inventory
        .seats
        .iter()
        .flat_map(|seat| seat.cohorts.iter().map(|cohort| cohort.id))
        .collect();
    if plan
        .families
        .iter()
        .any(|decision| !groups.contains(decision.group.as_str()))
        || plan
            .cases
            .iter()
            .any(|decision| !candidates.contains(decision.candidate.as_str()))
        || plan
            .cuts
            .iter()
            .any(|decision| !seats.contains(&decision.seat))
        || plan
            .cohorts
            .iter()
            .any(|decision| !cohorts.contains(&decision.cohort))
    {
        return Err(invalid(
            "an eval-authoring plan names what its inventory did not hold",
        ));
    }
    let bounded = |text: &str, max: usize| !text.trim().is_empty() && text.len() <= max;
    if plan.cases.iter().any(|decision| {
        decision
            .stratum
            .as_deref()
            .is_some_and(|stratum| !bounded(stratum, MAX_NAME_BYTES))
    }) || plan.cuts.iter().any(|decision| {
        decision.from >= decision.until || !bounded(&decision.rubric_revision, MAX_REF_BYTES)
    }) || plan
        .cohorts
        .iter()
        .any(|decision| decision.retire && !bounded(&decision.reason, MAX_REASON_BYTES))
    {
        return Err(invalid("an eval-authoring plan has a malformed field"));
    }
    Ok(())
}

/// Step one: each group gets its family, whole, before any case. A group
/// whose roots already have a family keeps its purpose and takes its fresh
/// roots; a new group takes the purpose the skill gave it, or waits.
fn assign_families(
    vault: &Vault,
    plan: &EvalAuthoringPlan,
    inventory: &EvalAuthoringInventory,
    now: u64,
    report: &mut EvalAuthoringReport,
) -> Result<()> {
    let mut asked: BTreeMap<&str, FamilyPurpose> = BTreeMap::new();
    for decision in &plan.families {
        asked
            .entry(decision.group.as_str())
            .or_insert(decision.purpose);
    }
    for group in &inventory.groups {
        if let Some(reason) = &group.blocked {
            report.skip(&group.id, reason);
            continue;
        }
        let purpose = match (group.purpose, asked.get(group.id.as_str())) {
            (Some(fixed), Some(purpose)) if fixed != *purpose => {
                report.skip(
                    &group.id,
                    "an eval family keeps the purpose it was assigned",
                );
                fixed
            }
            (Some(fixed), _) => fixed,
            (None, Some(purpose)) => *purpose,
            (None, None) => continue,
        };
        if group.fresh_roots == 0 {
            continue;
        }
        match vault.assign_eval_family(&group.seat, &group.root_set, purpose, now) {
            Ok(_) if group.family.is_some() => report.families_extended += 1,
            Ok(_) => report.families_assigned += 1,
            Err(error) => report.skip(&group.id, refusal(error)?),
        }
    }
    Ok(())
}

/// Step two: each kept candidate's case, reusing the one its receipt already
/// has, then every grounded label a case lacks.
fn record_cases(
    vault: &Vault,
    plan: &EvalAuthoringPlan,
    inventory: &EvalAuthoringInventory,
    now: u64,
    report: &mut EvalAuthoringReport,
) -> Result<()> {
    let mut kept: BTreeMap<&str, Option<&str>> = BTreeMap::new();
    for decision in &plan.cases {
        kept.entry(decision.candidate.as_str())
            .or_insert(decision.stratum.as_deref().map(str::trim));
    }
    for candidate in &inventory.candidates {
        let chosen = kept.get(candidate.id.as_str());
        let case = match (candidate.case, chosen) {
            (Some(case), _) => {
                if chosen.is_some() {
                    report.cases_reused += 1;
                }
                case
            }
            (None, None) => continue,
            (None, Some(stratum)) => {
                if candidate.labels.is_empty() {
                    report.skip(&candidate.id, "a case needs a grounded outcome label");
                    continue;
                }
                let draft = EvalCaseDraft {
                    seat: candidate.seat.clone(),
                    kind: DerivationKind::Receipt,
                    receipts: vec![candidate.id.clone()],
                    parents: Vec::new(),
                    stratum: stratum.map(str::to_owned),
                    draw_probability: None,
                    source_at: candidate.at,
                };
                match vault.record_eval_case(&draft, now) {
                    Ok(case) => {
                        report.cases_recorded += 1;
                        case.id
                    }
                    Err(error) => {
                        report.skip(&candidate.id, refusal(error)?);
                        continue;
                    }
                }
            }
        };
        for label in candidate.labels.iter().filter(|label| !label.held) {
            let label = EvalLabel {
                kind: label.kind,
                value: label.value.clone(),
                reference: label.reference.clone(),
                weight: 1.0,
                at: label.at,
            };
            match vault.label_eval_case(&case, label) {
                Ok(_) => report.labels_added += 1,
                Err(error) => report.skip(&candidate.id, refusal(error)?),
            }
        }
    }
    Ok(())
}

/// Step three: each cut, audited on the members it would take and committed
/// with that audit.
fn cut_cohorts(
    vault: &Vault,
    plan: &EvalAuthoringPlan,
    provenance: &AuditProvenance,
    now: u64,
    report: &mut EvalAuthoringReport,
) -> Result<()> {
    if plan.cuts.is_empty() {
        return Ok(());
    }
    let lineage = LineageReader::read(vault)?;
    for cut in &plan.cuts {
        let item = format!("cut {}..{}", cut.from, cut.until);
        let Some(audit) = prepare_cut_audit(
            vault,
            &lineage,
            &cut.seat,
            (cut.from, cut.until),
            provenance.clone(),
        )?
        else {
            report.skip(item, "no whole sealed family falls in this window");
            continue;
        };
        match vault.cut_eval_cohort(
            &cut.seat,
            cut.from,
            cut.until,
            cut.rubric_revision.trim(),
            cut.reference,
            &audit,
            now,
        ) {
            Ok(cohort) => {
                if !audit.complete() {
                    report.cuts_with_coverage_gaps += 1;
                }
                report.cohorts_cut.push(cohort.id);
            }
            Err(error) => report.skip(item, refusal(error)?),
        }
    }
    Ok(())
}

/// Step four: each retirement the skill decided, with its reason and the
/// exposure read now.
fn retire_cohorts(
    vault: &Vault,
    plan: &EvalAuthoringPlan,
    attempt: EntityId,
    skill: &(EntityId, String),
    now: u64,
    report: &mut EvalAuthoringReport,
) -> Result<()> {
    let mut seen = BTreeSet::new();
    for decision in &plan.cohorts {
        if !seen.insert(decision.cohort) {
            continue;
        }
        if !decision.retire {
            report.cohorts_kept += 1;
            continue;
        }
        let retirement = CohortRetirement {
            reason: decision.reason.trim().to_owned(),
            skill: skill.0,
            revision: skill.1.clone(),
            attempt,
            exposure: vault.eval_cohort_exposure(&decision.cohort)?,
        };
        let item = decision.cohort.to_hex();
        match vault.retire_eval_cohort(&decision.cohort, retirement, now) {
            Ok(row)
                if row
                    .retirement
                    .as_ref()
                    .is_some_and(|retired| retired.attempt == attempt) =>
            {
                report.cohorts_retired.push(row.id);
            }
            Ok(_) => report.skip(item, "the eval cohort had already retired"),
            Err(error) => report.skip(item, refusal(error)?),
        }
    }
    Ok(())
}

/// Applies the eval-authoring skill's `plan` for `inventory`, as the
/// authoring `attempt` running `skill` (its entity and revision): families
/// for whole groups first, then cases and their fixed-code labels, then each
/// cut with its audit, then retirements. A decision a door refuses, or a
/// group whose roots reach two families, is reported as skipped, never
/// forced.
/// # Errors
/// A plan for another inventory, naming what the inventory did not hold, or
/// with a malformed field, before anything applies; storage errors.
pub fn apply_eval_authoring_plan(
    vault: &Vault,
    attempt: AttemptId,
    skill: (EntityId, String),
    plan: EvalAuthoringPlan,
    inventory: &EvalAuthoringInventory,
    now: u64,
) -> Result<EvalAuthoringReport> {
    validate(&plan, inventory)?;
    let attempt = EntityId::from_bytes(*attempt.as_bytes())?;
    let mut report = EvalAuthoringReport::default();
    assign_families(vault, &plan, inventory, now, &mut report)?;
    record_cases(vault, &plan, inventory, now, &mut report)?;
    let provenance = AuditProvenance {
        attempt,
        skill: skill.0,
        revision: skill.1.clone(),
        inventory_digest: inventory.inventory_digest.clone(),
    };
    cut_cohorts(vault, &plan, &provenance, now, &mut report)?;
    retire_cohorts(vault, &plan, attempt, &skill, now, &mut report)?;
    Ok(report)
}
