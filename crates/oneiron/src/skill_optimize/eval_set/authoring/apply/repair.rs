//! Explicit Coach Repair choices reuse ordinary authoring and scoped audits.

use super::super::{eval_authoring_inventory_sourced, inventory_digest, seat_inventory};
use super::*;
use crate::memory::{Memory, MemoryResult};
use crate::skill_optimize::eval_set::cut_audit::prepare_cut_audit_scoped_listing;
use crate::skill_optimize::eval_set::{
    CASE_PREFIX, EvalCase, EvalRepairAuthoringSource, EvalRepairCaseReference,
    EvalRepairCaseRequest, EvalRepairNominations, FAMILY_PREFIX, SourceFamily, rows_in_txn,
};

/// A loaded authoring skill's ordinary plan beside its exact Repair choices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvalRepairAuthoringPlan {
    pub authoring: EvalAuthoringPlan,
    pub repairs: Vec<EvalRepairCaseRequest>,
}

/// Add the actual nomination seats, including seats with no receipt history yet.
/// The inventory remains metadata only and retains the ordinary digest rules.
pub(in crate::skill_optimize::eval_set) fn repair_authoring_inventory_sourced(
    vault: &Vault,
    nominations: &EvalRepairNominations,
    now: u64,
) -> Result<(EvalAuthoringInventory, Option<Vec<EntityId>>)> {
    let (mut inventory, rows) = eval_authoring_inventory_sourced(vault, now)?;
    let held: BTreeSet<_> = inventory
        .seats
        .iter()
        .map(|seat| seat.seat.clone())
        .collect();
    let extra: BTreeSet<_> = nominations
        .sources
        .iter()
        .flat_map(|source| &source.tasks)
        .filter_map(|read| read.as_ref().ok())
        .filter_map(|read| read.recipe.as_ref())
        .map(|recipe| recipe.source.seat.clone())
        .filter(|seat| !held.contains(seat))
        .collect();
    if !extra.is_empty() {
        let txn = vault.store.env.read_txn()?;
        let families = rows_in_txn::<SourceFamily>(vault, &txn, FAMILY_PREFIX)?;
        let cases = rows_in_txn::<EvalCase>(vault, &txn, CASE_PREFIX)?;
        for seat in &extra {
            inventory
                .seats
                .push(seat_inventory(vault, &txn, seat, &families, &cases)?);
        }
        inventory
            .seats
            .sort_by(|left, right| left.seat.cmp(&right.seat));
        inventory.inventory_digest = inventory_digest(&inventory)?;
    }
    let nomination_rows: Option<Vec<EntityId>> = nominations
        .sources
        .iter()
        .map(|source| EntityId::from_hex(&source.claim_ref).ok())
        .collect();
    let rows = crate::skill_optimize::union_source_rows([rows, nomination_rows]);
    Ok((inventory, rows))
}

/// Whole-plan validation precedes all writes. Repair admission precedes the
/// original scoped cut audit, and retirements retain the actual Skill author.
pub(in crate::skill_optimize::eval_set) fn apply_repair_authoring_plan(
    memory: &Memory<'_>,
    source: &EvalRepairAuthoringSource<'_>,
    input: EvalRepairAuthoringPlan,
    inventory: &EvalAuthoringInventory,
    author: (AttemptId, (EntityId, String)),
    now: u64,
    rows: &mut Vec<EntityId>,
) -> MemoryResult<EvalRepairCohortReport> {
    let vault = memory.vault();
    let plan = input.authoring;
    validate(&plan, inventory)?;
    if input
        .repairs
        .iter()
        .any(|input| !source.nominated(&input.recipe))
    {
        return Err(invalid("an eval-authoring plan names an un-nominated Repair task").into());
    }
    let (attempt, skill) = author;
    let attempt = EntityId::from_bytes(*attempt.as_bytes())?;
    let mut report = EvalAuthoringReport::default();
    assign_families(vault, &plan, inventory, now, &mut report)?;
    record_cases(vault, &plan, inventory, now, &mut report)?;
    let mut repairs = Vec::with_capacity(input.repairs.len());
    for input in &input.repairs {
        let read = source.record_case(input)?;
        if let Some(source_rows) = read
            .case
            .as_ref()
            .and_then(|case| case.source_rows.as_deref())
        {
            rows.extend_from_slice(source_rows);
        }
        repairs.push(EvalRepairCaseReference::from(read));
    }
    let provenance = AuditProvenance {
        author: EvalCutAuthor::Skill {
            attempt,
            skill: skill.0,
            revision: skill.1.clone(),
        },
        inventory_digest: inventory.inventory_digest.clone(),
    };
    if !plan.cuts.is_empty() {
        let lineage = LineageReader::read(vault)?;
        for cut in &plan.cuts {
            let read = prepare_cut_audit_scoped_listing(
                memory,
                &lineage,
                &cut.seat,
                (cut.from, cut.until),
                provenance.clone(),
                rows,
            )?;
            report.source_receipts.extend(read.receipts);
            apply_cut(vault, cut, read.audit, now, &mut report)?;
        }
    }
    retire_cohorts(vault, &plan, attempt, &skill, now, &mut report)?;
    Ok(EvalRepairCohortReport {
        authoring: report,
        repairs,
    })
}
