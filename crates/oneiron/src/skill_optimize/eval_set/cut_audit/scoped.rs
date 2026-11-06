//! Repair comparison inputs admitted by the original Memory handle. Only
//! ephemeral shingles cross into the audit; source text and graders do not.

use super::super::repair_case::read_repair_task_in_txn;
use super::super::{DerivationKind, case_in_txn};
use super::*;
use crate::claim::{ClaimReadStatus, ScopedReadReceipt};
use crate::memory::{Memory, MemoryResult};

pub(in crate::skill_optimize::eval_set) struct ScopedCutAudit {
    pub(in crate::skill_optimize::eval_set) audit: Option<EvalCutAuditDraft>,
    pub(in crate::skill_optimize::eval_set) receipts: Vec<ScopedReadReceipt>,
}

type RepairShingles = BTreeMap<EntityId, (EntityId, Option<Shingles>)>;

fn case_shingles_scoped_listing(
    vault: &Vault,
    lineage: &LineageReader,
    cases: &[AuditCase],
    repairs: &RepairShingles,
    gaps: &mut Vec<CoverageGap>,
    rows: &mut Vec<EntityId>,
) -> Result<Vec<(EntityId, Shingles)>> {
    let mut read = Vec::with_capacity(cases.len());
    for case in cases {
        if let Some((source, set)) = repairs.get(&case.case) {
            match set {
                Some(set) if !set.is_empty() => read.push((case.case, set.clone())),
                _ => gaps.push(CoverageGap {
                    case: case.case,
                    source: Some(format!("entity:{}", source.to_hex())),
                }),
            }
        } else {
            read.extend(case_shingles_listing(
                vault,
                lineage,
                std::slice::from_ref(case),
                gaps,
                rows,
            )?);
        }
    }
    Ok(read)
}

pub(in crate::skill_optimize::eval_set) fn prepare_cut_audit_scoped_listing(
    memory: &Memory<'_>,
    lineage: &LineageReader,
    seat: &EvalSeat,
    window: (u64, u64),
    provenance: AuditProvenance,
    rows: &mut Vec<EntityId>,
) -> MemoryResult<ScopedCutAudit> {
    let vault = memory.vault();
    let (from, until) = window;
    let needs_lane = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let Some((members, compared)) = audit_cases_in_txn(vault, &txn, seat, from, until)? else {
            return Ok(ScopedCutAudit {
                audit: None,
                receipts: Vec::new(),
            });
        };
        let mut repair = false;
        for case in members.iter().chain(&compared) {
            let member = case_in_txn(vault, &txn, &case.case)?
                .ok_or(Error::CorruptedIndex("eval audit case"))?;
            repair |= member.repair_task.is_some();
        }
        repair
    };
    // Receipt/Synthetic cuts keep their existing reader and need no new grant.
    if !needs_lane {
        return Ok(ScopedCutAudit {
            audit: prepare_cut_audit_listing(vault, lineage, seat, window, provenance, rows)?,
            receipts: Vec::new(),
        });
    }
    let lane = memory.read_lane(ClaimReadStatus::Recorded)?;
    lane.persist_grant_clock()?;
    let _bodies = vault.pin_all_result_bodies();
    let (members, compared, repairs, receipts) = {
        let txn = vault.store.env.read_txn().map_err(Error::from)?;
        let Some((members, compared)) = audit_cases_in_txn(vault, &txn, seat, from, until)? else {
            return Ok(ScopedCutAudit {
                audit: None,
                receipts: Vec::new(),
            });
        };
        let mut repairs = BTreeMap::new();
        let mut receipts = Vec::new();
        for case in members.iter().chain(&compared) {
            let member = case_in_txn(vault, &txn, &case.case)?
                .ok_or(Error::CorruptedIndex("eval audit case"))?;
            let Some(recipe) = member.repair_task.as_ref() else {
                continue;
            };
            let family = family_in_txn(vault, &txn, &member.family)?
                .ok_or(Error::CorruptedIndex("Repair case family"))?;
            let id = EntityId::from_hex(&recipe.source.claim_ref)?;
            let root = format!("entity:{}", id.to_hex());
            if member.kind != DerivationKind::Repair
                || member.seat != recipe.source.seat
                || &member.seat != seat
                || family.seat != member.seat
                || !family.roots.contains(&root)
                || member.receipts.as_slice() != [root]
                || !member.parents.is_empty()
                || member.source_rows.as_deref() != Some([id].as_slice())
            {
                return Err(Error::CorruptedIndex("Repair case recipe binding").into());
            }
            let read = read_repair_task_in_txn(vault, &txn, &lane, recipe)?;
            let set = match read.value {
                Some(task) => {
                    let text = serde_json::to_string(task.response_input())
                        .map_err(|_| Error::InvalidClaimBody("Repair task encoding failed"))?;
                    rows.push(id);
                    Some(shingles(&[text]))
                }
                None => None,
            };
            receipts.push(read.receipt);
            repairs.insert(member.id, (id, set));
        }
        (members, compared, repairs, receipts)
    };
    // The legacy lineage/retained-text readers open their own snapshots.
    let mut gaps = Vec::new();
    let left = case_shingles_scoped_listing(vault, lineage, &members, &repairs, &mut gaps, rows)?;
    let right = case_shingles_scoped_listing(vault, lineage, &compared, &repairs, &mut gaps, rows)?;
    let (comparisons, flags) = near_copy_flags(&left, &right);
    let member_ids: Vec<EntityId> = members.iter().map(|case| case.case).collect();
    Ok(ScopedCutAudit {
        audit: Some(EvalCutAuditDraft {
            seat: seat.clone(),
            from,
            until,
            provenance,
            membership_digest: membership_digest(&member_ids),
            members,
            compared,
            comparisons,
            flags,
            gaps,
        }),
        receipts,
    })
}
