//! The eval-authoring inventory and the rows it was read from, in one set of
//! reads (FIX 6997): the Coach's eval-authoring call's permit and its metered
//! settlement carry the rows, and `eval_authoring_inventory` returns the same
//! inventory without them. The set stays known only while every candidate
//! and label names the rows it was read from.
use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use serde_json::Value;

use super::super::cohort::{EXPOSURE_PREFIX, is_space_probe_seat};
use super::super::repair_seed::seeds_in_txn;
use super::super::{
    CASE_PREFIX, DerivationKind, EvalCase, EvalExposure, EvalRepairSeedState, EvalRepairTaskSpec,
    EvalSeat, FAMILY_PREFIX, SourceFamily, rows_in_txn,
};
use super::{
    CandidateLabel, EVAL_AUTHORING_WINDOW_SECS, EvalAuthoringInventory, EvalCandidate,
    EvalRepairCandidate, EvalRepairSeedStanding, EvalRepairSeedSummary, EvalSkillPair,
    LineageReader, Sourced, group_by_roots, inventory_digest, recent_candidates, seat_inventory,
    source_group,
};
use crate::Vault;
use crate::claim::ClaimApprovalStatus;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::ingest::{AgUiRepairLinkStatus, ag_ui_captures_in_txn};
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillContentHash, SkillLifecycle};
use crate::skill_optimize::gate::target_of;
use crate::skill_optimize::union_source_rows;

/// The RFC 6901 pointer of every object in `failure` that reads as a repair
/// task contract, depth-first: objects and arrays to depth 8, at most 4096
/// nodes. Only an object holding a contract's `world` and `grader` is tried,
/// in place.
fn task_pointers(failure: &Value) -> Vec<String> {
    fn escape(token: &str) -> String {
        token.replace('~', "~0").replace('/', "~1")
    }
    let mut pointers = Vec::new();
    let mut stack: Vec<(String, &Value, u8)> = vec![(String::new(), failure, 0)];
    let mut nodes = 0;
    while let Some((pointer, value, depth)) = stack.pop() {
        nodes += 1;
        if nodes > 4096 {
            break;
        }
        if let Value::Object(fields) = value
            && fields.contains_key("world")
            && fields.contains_key("grader")
            && EvalRepairTaskSpec::deserialize(value).is_ok()
        {
            pointers.push(pointer.clone());
        }
        if depth == 8 {
            continue;
        }
        match value {
            Value::Object(fields) => {
                for (key, child) in fields.iter().rev() {
                    stack.push((format!("{pointer}/{}", escape(key)), child, depth + 1));
                }
            }
            Value::Array(items) => {
                for (index, child) in items.iter().enumerate().rev() {
                    stack.push((format!("{pointer}/{index}"), child, depth + 1));
                }
            }
            _ => {}
        }
    }
    pointers
}

/// [`eval_authoring_inventory`](super::eval_authoring_inventory) beside the
/// rows it was read from, in the same reads: each candidate's recorded
/// attempt-input set and its labels' rows, the TURNs, proposal artifacts and
/// derived-from entities its lineage reached, every case and family, and
/// each seat's cohorts with their exposures. The rows are `None`, unknown,
/// when any candidate or label has no complete set. The space probes'
/// reserved `space_probe.<kind>` metadata seats are skipped (FIX 7041).
/// # Errors
/// Unreadable rows, or storage errors.
pub fn eval_authoring_inventory_sourced(
    vault: &Vault,
    now: u64,
) -> Result<(EvalAuthoringInventory, Option<Vec<EntityId>>)> {
    let from = now.saturating_sub(EVAL_AUTHORING_WINDOW_SECS);
    let lineage = LineageReader::read(vault)?;
    let mut sourced = Vec::new();
    for (receipt, seat) in recent_candidates(vault, from, now)? {
        let resolved = lineage.resolve(vault, &receipt)?;
        // A session turn is pipeline-inert: nothing derives from it.
        if !resolved.off_record {
            sourced.push(Sourced {
                receipt,
                seat,
                lineage: resolved,
            });
        }
    }
    let txn = vault.store.env.read_txn()?;
    let cases = rows_in_txn::<EvalCase>(vault, &txn, CASE_PREFIX)?;
    let families = rows_in_txn::<SourceFamily>(vault, &txn, FAMILY_PREFIX)?;
    // A case is reused when it reads exactly the candidate's receipt.
    let mut by_receipt: BTreeMap<(&EvalSeat, &str), &EvalCase> = BTreeMap::new();
    for case in &cases {
        if let [receipt] = case.receipts.as_slice()
            && case.parents.is_empty()
            && case.kind == DerivationKind::Receipt
        {
            by_receipt
                .entry((&case.seat, receipt.as_str()))
                .or_insert(case);
        }
    }
    let mut groups = Vec::new();
    let mut candidates = Vec::new();
    for (number, members) in group_by_roots(&sourced).into_iter().enumerate() {
        let id = format!("g{}", number + 1);
        let members: Vec<&Sourced> = members.into_iter().map(|index| &sourced[index]).collect();
        for member in &members {
            let case = by_receipt
                .get(&(&member.seat, member.receipt.receipt_id.as_str()))
                .copied();
            let labels = member
                .lineage
                .labels
                .iter()
                .map(|label| CandidateLabel {
                    held: case.is_some_and(|case| {
                        case.labels.iter().any(|held| {
                            held.kind == label.kind && held.reference == label.reference
                        })
                    }),
                    ..label.clone()
                })
                .collect();
            candidates.push(EvalCandidate {
                id: member.receipt.receipt_id.clone(),
                seat: member.seat.clone(),
                group: id.clone(),
                at: member.receipt.occurred_at,
                labels,
                case: case.map(|case| case.id),
                source_rows: member.lineage.sources.clone(),
            });
        }
        groups.push(source_group(vault, &txn, id, &members)?);
    }
    let seats: BTreeSet<&EvalSeat> = sourced
        .iter()
        .map(|item| &item.seat)
        .chain(families.iter().map(|family| &family.seat))
        .filter(|seat| !is_space_probe_seat(seat))
        .collect();
    let mut seat_rows = Vec::with_capacity(seats.len());
    for seat in seats {
        seat_rows.push(seat_inventory(vault, &txn, seat, &families, &cases)?);
    }
    // The rows the inventory read, in the same snapshot: every case and
    // family, the lineage's TURNs, artifacts and derived-from entities, each
    // cohort with the exposures its counts came from, and below each listed
    // capture claim and skill.
    let mut read: Vec<EntityId> = cases
        .iter()
        .map(|case| case.id)
        .chain(families.iter().map(|family| family.id))
        .collect();
    for item in &sourced {
        read.extend(item.lineage.turns.iter().copied());
        read.extend(item.lineage.artifacts.iter().copied());
        if let Ok(fields) = item.receipt.pack_attribution_fields() {
            read.extend(
                fields
                    .used_edges
                    .iter()
                    .flat_map(|edge| [edge.derived, edge.source]),
            );
        }
    }
    for cohort in seat_rows.iter().flat_map(|seat| &seat.cohorts) {
        read.push(cohort.id);
        let prefix = [EXPOSURE_PREFIX, cohort.id.as_bytes()].concat();
        for exposure in rows_in_txn::<EvalExposure>(vault, &txn, &prefix)? {
            read.push(exposure.id);
        }
    }
    // One row per task contract on a linked repair: the repair the skill
    // may seed, with every stored seed of its task.
    let mut repairs = Vec::new();
    let captures = ag_ui_captures_in_txn(vault, &txn, from, now.saturating_add(1), 64)?;
    let seeds = seeds_in_txn(vault, &txn)?;
    for meta in &captures {
        read.push(meta.claim);
        for link in meta
            .repair_links
            .iter()
            .filter(|link| link.status == AgUiRepairLinkStatus::Linked)
        {
            let Some(failure_ordinal) = link.failure_ordinal else {
                continue;
            };
            let Some(failure) = meta.events.get(failure_ordinal) else {
                continue;
            };
            for task_pointer in task_pointers(failure.raw()) {
                let mut summaries: Vec<EvalRepairSeedSummary> = seeds
                    .iter()
                    .filter(|seed| {
                        seed.source.claim_ref == meta.claim_ref
                            && seed.source.source_hash == meta.source_hash
                            && seed.source.outcome_ordinal == link.outcome_ordinal
                            && seed.source.task_pointer == task_pointer
                    })
                    .map(|seed| EvalRepairSeedSummary {
                        seat: seed.source.seat.clone(),
                        standing: match &seed.state {
                            EvalRepairSeedState::Pending => EvalRepairSeedStanding::Pending,
                            EvalRepairSeedState::AwaitingLabel => {
                                EvalRepairSeedStanding::AwaitingLabel
                            }
                            EvalRepairSeedState::Confirmed { .. } => {
                                EvalRepairSeedStanding::Confirmed
                            }
                            EvalRepairSeedState::Refused { reason, .. } => {
                                EvalRepairSeedStanding::Refused { reason: *reason }
                            }
                        },
                    })
                    .collect();
                summaries.sort_by(|a, b| a.seat.cmp(&b.seat));
                repairs.push(EvalRepairCandidate {
                    id: format!("r{}", repairs.len() + 1),
                    claim_ref: meta.claim_ref.clone(),
                    source_hash: meta.source_hash.clone(),
                    outcome_ordinal: link.outcome_ordinal,
                    task_pointer,
                    app_id: meta.app_id.clone(),
                    at: meta.at,
                    seeds: summaries,
                    owner: Some(meta.owner),
                });
            }
        }
    }
    // One row per open revision with a hashed predecessor: the old and
    // candidate arms a repair seed compares.
    let mut skill_pairs = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_SKILL)? {
        let Some(record) = vault.get_skill_record_in_txn(&txn, &id)? else {
            continue;
        };
        if record.lifecycle_status != SkillLifecycle::Candidate
            || record.approval_status != ClaimApprovalStatus::Proposed
        {
            continue;
        }
        let Some(candidate) = record.content_hash.as_ref().map(SkillContentHash::to_hex) else {
            continue;
        };
        let predecessor = target_of(&record).ok().or(record.forked_from);
        let Some(predecessor) = predecessor else {
            continue;
        };
        let Some(old) = vault
            .get_skill_record_in_txn(&txn, &predecessor)?
            .and_then(|parent| parent.content_hash.as_ref().map(SkillContentHash::to_hex))
        else {
            continue;
        };
        read.push(id);
        skill_pairs.push(EvalSkillPair {
            id: format!("k{}", skill_pairs.len() + 1),
            skill: id,
            name: record.skill_id.clone(),
            candidate,
            old,
        });
    }
    let rows = union_source_rows(
        candidates
            .iter()
            .flat_map(|candidate| {
                std::iter::once(candidate.source_rows.as_deref()).chain(
                    candidate
                        .labels
                        .iter()
                        .map(|label| label.source_rows.as_deref()),
                )
            })
            .chain([Some(read.as_slice())]),
    );
    let mut inventory = EvalAuthoringInventory {
        inventory_digest: String::new(),
        built_at: now,
        from,
        groups,
        candidates,
        seats: seat_rows,
        repairs,
        skill_pairs,
    };
    inventory.inventory_digest = inventory_digest(&inventory)?;
    Ok((inventory, rows))
}
