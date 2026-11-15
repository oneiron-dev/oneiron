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
use super::super::repair_task::task_contract_key;
use super::super::{
    CASE_PREFIX, DerivationKind, EvalCase, EvalExposure, EvalRepairSeed, EvalRepairSeedState,
    EvalRepairTaskSpec, EvalSeat, FAMILY_PREFIX, SourceFamily, rows_in_txn,
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
use crate::ports::raw_readable_in_txn;
use crate::registry::ENTITY_TYPE_SKILL;
use crate::skill::{SkillContentHash, SkillLifecycle};
use crate::skill_optimize::gate::target_of;
use crate::skill_optimize::union_source_rows;

/// The captures, and below them the rows, the inventory lists at most: the
/// newest in the window first.
const MAX_REPAIR_CAPTURES: usize = 64;
const MAX_REPAIR_ROWS: usize = 64;
/// The task contracts one failure event lists at most.
const MAX_TASK_CONTRACTS_PER_FAILURE: usize = 8;
/// The nodes one failure event's walk visits at most, and its depth.
const MAX_CONTRACT_WALK_NODES: usize = 4096;
const MAX_CONTRACT_WALK_DEPTH: u8 = 8;
/// The open skill revisions the inventory lists at most.
const MAX_SKILL_PAIR_ROWS: usize = 64;

/// The RFC 6901 pointer of each object in `failure` that reads as a repair
/// task contract, with the contract's key, depth-first, at most
/// [`MAX_TASK_CONTRACTS_PER_FAILURE`]:
/// objects and arrays to [`MAX_CONTRACT_WALK_DEPTH`], at most
/// [`MAX_CONTRACT_WALK_NODES`] nodes, counted as they are stacked, so a wide
/// container stops the walk's growth. Only an object holding a contract's
/// `world` and `grader` is tried, in place.
fn task_contracts(failure: &Value) -> Vec<(String, [u8; 32])> {
    fn escape(token: &str) -> String {
        token.replace('~', "~0").replace('/', "~1")
    }
    let mut contracts = Vec::new();
    let mut stack: Vec<(String, &Value, u8)> = vec![(String::new(), failure, 0)];
    let mut stacked = 1;
    while let Some((pointer, value, depth)) = stack.pop() {
        if let Value::Object(fields) = value
            && fields.contains_key("world")
            && fields.contains_key("grader")
            && let Ok(spec) = EvalRepairTaskSpec::deserialize(value)
            && let Ok(key) = task_contract_key(&spec)
        {
            contracts.push((pointer.clone(), key));
            if contracts.len() == MAX_TASK_CONTRACTS_PER_FAILURE {
                break;
            }
        }
        if depth == MAX_CONTRACT_WALK_DEPTH {
            continue;
        }
        let room = MAX_CONTRACT_WALK_NODES - stacked;
        let children: Vec<(String, &Value, u8)> = match value {
            Value::Object(fields) => fields
                .iter()
                .take(room)
                .map(|(key, child)| (format!("{pointer}/{}", escape(key)), child, depth + 1))
                .collect(),
            Value::Array(items) => items
                .iter()
                .take(room)
                .enumerate()
                .map(|(index, child)| (format!("{pointer}/{index}"), child, depth + 1))
                .collect(),
            _ => Vec::new(),
        };
        stacked += children.len();
        stack.extend(children.into_iter().rev());
    }
    contracts
}

/// Where the inventory shows a stored seed: its source's capture, outcome
/// and task pointer.
type SeedTaskKey<'a> = (&'a str, &'a str, usize, &'a str);

/// Whether every row `seed` was compiled from still reads in this snapshot,
/// by the capture listing's rule ([`raw_readable_in_txn`]): present, and not
/// deleted, withdrawn, stale or source-withdrawn.
fn seed_capture_reads_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    seed: &EvalRepairSeed,
) -> Result<bool> {
    for id in &seed.source_rows {
        let Some(raw) = vault.get_raw_in(txn, id)? else {
            return Ok(false);
        };
        if !raw_readable_in_txn(&vault.store, txn, id, &raw)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Every stored seed, by its task and by its task contract: one pass over
/// the seeds, whatever the repair rows.
struct SeedIndex<'a> {
    seeds: &'a [EvalRepairSeed],
    by_task: BTreeMap<SeedTaskKey<'a>, Vec<usize>>,
    by_contract: BTreeMap<[u8; 32], Vec<usize>>,
}

impl<'a> SeedIndex<'a> {
    fn new(seeds: &'a [EvalRepairSeed]) -> Self {
        let mut by_task: BTreeMap<SeedTaskKey<'a>, Vec<usize>> = BTreeMap::new();
        let mut by_contract: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
        for (index, seed) in seeds.iter().enumerate() {
            let source = &seed.source;
            by_task
                .entry((
                    source.claim_ref.as_str(),
                    source.source_hash.as_str(),
                    source.outcome_ordinal,
                    source.task_pointer.as_str(),
                ))
                .or_default()
                .push(index);
            if let Some(key) = seed.contract_key {
                by_contract.entry(key).or_default().push(index);
            }
        }
        Self {
            seeds,
            by_task,
            by_contract,
        }
    }

    /// Every seed of a repair row, in seat order: its task's own, and every
    /// seed of the same contract from another source or seat whose capture
    /// still reads in `txn` (RULING UNBUILT-P05E-CONTRACT-ALIAS = A). `None`
    /// when the row has none and its contract is held by a seed whose
    /// capture no longer reads: the row can take no seed until the erase
    /// takes that one, and shows nothing of it (RULING
    /// UNBUILT-P05E-WITHDRAWN-SEED = A).
    fn seeds_of(
        &self,
        vault: &Vault,
        txn: &heed::RoTxn<'_>,
        task: SeedTaskKey<'_>,
        contract: &[u8; 32],
    ) -> Result<Option<Vec<&'a EvalRepairSeed>>> {
        let mut rows: BTreeSet<usize> = self
            .by_task
            .get(&task)
            .into_iter()
            .flatten()
            .copied()
            .collect();
        let held = self
            .by_contract
            .get(contract)
            .map_or(&[][..], Vec::as_slice);
        for &index in held {
            if !rows.contains(&index) && seed_capture_reads_in_txn(vault, txn, &self.seeds[index])?
            {
                rows.insert(index);
            }
        }
        if rows.is_empty() && !held.is_empty() {
            return Ok(None);
        }
        let mut seeds: Vec<&'a EvalRepairSeed> =
            rows.into_iter().map(|index| &self.seeds[index]).collect();
        seeds.sort_by(|a, b| a.source.seat.cmp(&b.source.seat));
        Ok(Some(seeds))
    }
}

/// A seed's seat and standing, as a repair row shows them.
fn seed_summary(seed: &EvalRepairSeed) -> EvalRepairSeedSummary {
    EvalRepairSeedSummary {
        seat: seed.source.seat.clone(),
        standing: match &seed.state {
            EvalRepairSeedState::Pending => EvalRepairSeedStanding::Pending,
            EvalRepairSeedState::AwaitingLabel => EvalRepairSeedStanding::AwaitingLabel,
            EvalRepairSeedState::Confirmed { .. } => EvalRepairSeedStanding::Confirmed,
            EvalRepairSeedState::Refused { reason, .. } => {
                EvalRepairSeedStanding::Refused { reason: *reason }
            }
        },
    }
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
    // may seed, with every stored seed of its task, whose captures join the
    // rows read. Each failure event is walked once, however many outcomes
    // link to it.
    let mut repairs = Vec::new();
    let captures = ag_ui_captures_in_txn(
        vault,
        &txn,
        from,
        now.saturating_add(1),
        MAX_REPAIR_CAPTURES,
    )?;
    let seeds = seeds_in_txn(vault, &txn)?;
    let seed_index = SeedIndex::new(&seeds);
    'captures: for meta in &captures {
        read.push(meta.claim);
        let mut contracts: BTreeMap<usize, Vec<(String, [u8; 32])>> = BTreeMap::new();
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
            let listed = contracts
                .entry(failure_ordinal)
                .or_insert_with(|| task_contracts(failure.raw()));
            for (task_pointer, contract_key) in listed.iter() {
                if repairs.len() == MAX_REPAIR_ROWS {
                    break 'captures;
                }
                let Some(row_seeds) = seed_index.seeds_of(
                    vault,
                    &txn,
                    (
                        meta.claim_ref.as_str(),
                        meta.source_hash.as_str(),
                        link.outcome_ordinal,
                        task_pointer.as_str(),
                    ),
                    contract_key,
                )?
                else {
                    continue;
                };
                for seed in &row_seeds {
                    read.extend(seed.source_rows.iter().copied());
                }
                repairs.push(EvalRepairCandidate {
                    id: format!("r{}", repairs.len() + 1),
                    claim_ref: meta.claim_ref.clone(),
                    source_hash: meta.source_hash.clone(),
                    outcome_ordinal: link.outcome_ordinal,
                    task_pointer: task_pointer.clone(),
                    app_id: meta.app_id.clone(),
                    at: meta.at,
                    seeds: row_seeds.into_iter().map(seed_summary).collect(),
                    owner: Some(meta.owner),
                });
            }
        }
    }
    // One row per open revision with a hashed predecessor: the old and
    // candidate arms a repair seed compares.
    let mut skill_pairs = Vec::new();
    for id in vault.entities_by_type(ENTITY_TYPE_SKILL)? {
        if skill_pairs.len() == MAX_SKILL_PAIR_ROWS {
            break;
        }
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
