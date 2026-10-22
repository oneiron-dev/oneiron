//! The browser library's records (moved out of `browser_library` whole): its
//! programs' and retires' rows, filed, counted, retired, resolved and read.

use std::cmp::Reverse;

use oneiron_browser::{
    RunOutcome, SupersedeOutcome, SupersedeRefusal, WorkflowProgram, WorkflowProof,
};

use super::index::{index_failure_in_txn, index_filing_in_txn, index_retire_in_txn};
#[cfg(doc)]
use super::type_filter;
use super::{
    DRIFT_REASON, FiledScope, Filing, LibraryActor, RETIRE_FILER_ONLY, RETIRED, RecentOutcome,
    Retired, RetiredWorkflow, STRICT_MISSES_BEFORE_DRIFT, WORKFLOWS, WorkflowRecord,
    WorkflowResolution, push_recent, strict_misses_after, superseded_by, superseded_reason,
};
use crate::Vault;
use crate::batch::secret_scan::{admitted_from, named_tree};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::TypeRef;
use crate::task_type::{PlacementDecisions, PlacementRequest, TaskTypeRef, place_type_ref};

pub(super) fn site_key(site: &str) -> [u8; 32] {
    *blake3::hash(site.as_bytes()).as_bytes()
}

/// Whether a program filed at `filed` is of the task type `wanted`: the
/// same node at the same tree version, with no descendant read in and no
/// other version's node put in its place. A version past what a filed
/// stamp holds matches nothing.
fn of_type(filed: &TypeRef, wanted: &TaskTypeRef) -> bool {
    filed.node_id == wanted.node_id && u64::from(filed.tree_version) == wanted.tree_version
}

/// The programs filed for `site` whose subgoal holds every word of
/// `subgoal`, ignoring case, and, with `type_ref`, whose task type it is
/// ([`type_filter`]): the most runs that met their postcondition first,
/// then the newest. Finding places nothing and asks no model.
///
/// # Errors
///
/// Storage errors.
pub fn site_workflows(
    vault: &Vault,
    site: &str,
    subgoal: Option<&str>,
    type_ref: Option<&TaskTypeRef>,
) -> Result<Vec<WorkflowRecord>> {
    let words: Vec<String> = subgoal
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_lowercase)
        .collect();
    let rtxn = vault.store.env.read_txn()?;
    let mut records: Vec<WorkflowRecord> = WORKFLOWS
        .scan_from(&vault.store, &rtxn, &site_key(site))?
        .into_iter()
        .map(|(_, record)| record)
        .filter(|record| {
            let filed = record.program.subgoal.to_lowercase();
            words.iter().all(|word| filed.contains(word.as_str()))
                && type_ref.is_none_or(|wanted| of_type(&record.type_ref, wanted))
        })
        .collect();
    records.sort_by_key(|record| {
        Reverse((record.runs.saturating_sub(record.failures), record.filed_at))
    });
    Ok(records)
}

/// The program filed under `id`.
///
/// # Errors
///
/// Storage errors.
pub fn workflow(vault: &Vault, id: EntityId) -> Result<Option<WorkflowRecord>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(WORKFLOWS
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, record)| record)
        .find(|record| record.id == id))
}

/// The program a `supersedes` link names, as its site's library holds it.
enum Predecessor {
    Live(WorkflowRecord),
    Retired(RetiredWorkflow),
}

/// The program `id` names among `site`'s, live or retired, in `txn`.
fn predecessor_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    site: &str,
    id: EntityId,
) -> Result<Option<Predecessor>> {
    if let Some(record) = WORKFLOWS.get(&vault.store, txn, &(site_key(site), id))? {
        return Ok(Some(Predecessor::Live(record)));
    }
    let retired = RETIRED.get(&vault.store, txn, &id)?;
    Ok(retired
        .filter(|trace| trace.record.site == site)
        .map(Predecessor::Retired))
}

/// The refusal a `supersedes` link to `old` would meet when `by` files a
/// program for `site` (FIX 7876), read before its replay: no program of
/// the site, or a live one `by` may not retire ([`RETIRE_FILER_ONLY`]).
/// [`file_workflow`] checks it again in its own write.
///
/// # Errors
///
/// Storage errors.
pub fn supersedes_refusal(
    vault: &Vault,
    by: EntityId,
    site: &str,
    old: EntityId,
) -> Result<Option<SupersedeRefusal>> {
    let rtxn = vault.store.env.read_txn()?;
    Ok(match predecessor_in_txn(vault, &rtxn, site, old)? {
        None => Some(SupersedeRefusal::NotOnSite),
        Some(Predecessor::Live(record)) if RETIRE_FILER_ONLY && !record.filed_by.is(by) => {
            Some(SupersedeRefusal::NotFiler)
        }
        Some(_) => None,
    })
}

/// Files `program` for `site` once both checks passed (`proof`), from
/// `by`'s run, stamped with the task type the host's placement ladder
/// (`decisions`) reads; without one the rule rung reads alone. The same
/// program filed again keeps its id, its runs and its seed, and takes the
/// new proof; a `supersedes` link on it is dropped, as no repair.
///
/// `filed_scope` is the solved group the filing's caller files it in (CUA
/// E8a); the same write moves the group's coverage, from the group a refile
/// held it in before, read in that write.
///
/// A new program that `supersedes` one of `site`'s, live or retired, is
/// filed as its successor, with its lineage's recent outcomes and one
/// repair more; in the same write a live one retires
/// [`superseded_reason`] at `by`'s word, as `library.retire` would retire
/// it ([`RETIRE_FILER_ONLY`]), and a retired one is only linked. A link to
/// no program of the site, to the program refiled, or to a live program
/// `by` may not retire, is refused before anything is filed.
///
/// # Errors
///
/// Storage errors.
#[expect(
    clippy::too_many_arguments,
    reason = "each argument is one part of the filing the host checked"
)]
pub fn file_workflow(
    vault: &Vault,
    by: EntityId,
    site: &str,
    program: &WorkflowProgram,
    proof: &WorkflowProof,
    at: u64,
    decisions: Option<&PlacementDecisions<'_>>,
    supersedes: Option<EntityId>,
    filed_scope: Option<FiledScope>,
) -> Result<Filing> {
    let same = serde_json::to_value(program).ok();
    // A filed program holds handles where this one may hold the secrets the
    // side-row wall lifted (OF-067); it is still the same program.
    let mut filed = None;
    for record in site_workflows(vault, site, None, None)? {
        if serde_json::to_value(&record.program).ok() == same
            || admitted_from(&named_tree(&record.program)?, &named_tree(program)?)?
        {
            filed = Some(record);
            break;
        }
    }
    let type_ref = place_type_ref(
        vault,
        None,
        &PlacementRequest::new(Some(program.subgoal.clone()), Some(site.to_owned())),
        decisions,
    )?;
    vault.with_write_txn_grouped(|wtxn| {
        let predecessor = match supersedes {
            Some(old) => match predecessor_in_txn(vault, wtxn, site, old)? {
                Some(predecessor) => Some(predecessor),
                None => return Ok(Filing::Refused(SupersedeRefusal::NotOnSite)),
            },
            None => None,
        };
        if let Some(mut record) = filed {
            if supersedes == Some(record.id) {
                return Ok(Filing::Refused(SupersedeRefusal::SameRecord));
            }
            let key = (site_key(site), record.id);
            let prior = WORKFLOWS.get(&vault.store, wtxn, &key)?;
            let seed = record.proof.seed.take().or_else(|| proof.seed.clone());
            let mut record = WorkflowRecord {
                type_ref,
                proof: WorkflowProof {
                    seed,
                    ..proof.clone()
                },
                filed_by: LibraryActor::Actor(by),
                filed_at: at,
                // A passing re-admission starts the miss streak again, as
                // a strict pass does (FIX 8048).
                strict_misses: 0,
                filed_scope: filed_scope.clone(),
                ..record
            };
            // The index reads the record as the side-row wall keeps it.
            WORKFLOWS.admit(vault, wtxn, &key, &mut record)?;
            WORKFLOWS.put(vault, wtxn, &key, &record)?;
            index_filing_in_txn(vault, wtxn, prior.as_ref(), &record)?;
            let superseded = predecessor.map(|_| SupersedeOutcome::Dropped);
            return Ok(Filing::Filed {
                id: record.id,
                superseded,
            });
        }
        let id = EntityId::now();
        let (mut recent, retire, superseded) = match predecessor {
            Some(Predecessor::Live(old)) => {
                if RETIRE_FILER_ONLY && !old.filed_by.is(by) {
                    return Ok(Filing::Refused(SupersedeRefusal::NotFiler));
                }
                let recent = old.recent.clone();
                (recent, Some(old), Some(SupersedeOutcome::Retired))
            }
            Some(Predecessor::Retired(old)) => {
                (old.record.recent, None, Some(SupersedeOutcome::Linked))
            }
            None => (Vec::new(), None, None),
        };
        if superseded.is_some() {
            push_recent(&mut recent, RecentOutcome::Repair, at);
        }
        let mut record = WorkflowRecord {
            id,
            site: site.to_owned(),
            program: program.clone(),
            type_ref,
            proof: proof.clone(),
            filed_by: LibraryActor::Actor(by),
            filed_at: at,
            runs: 0,
            failures: 0,
            last_run_at: None,
            supersedes,
            recent,
            strict_misses: 0,
            filed_scope: filed_scope.clone(),
        };
        let key = (site_key(site), id);
        WORKFLOWS.admit(vault, wtxn, &key, &mut record)?;
        WORKFLOWS.put(vault, wtxn, &key, &record)?;
        index_filing_in_txn(vault, wtxn, None, &record)?;
        if let Some(old) = retire {
            let reason = superseded_reason(id);
            retire_in_txn(vault, wtxn, old, by, Some(reason.as_str()), at)?;
        }
        Ok(Filing::Filed { id, superseded })
    })
}

/// Counts one library run of `id` from `by`'s call at `at`: whether it met
/// its postcondition, among its lineage's recent outcomes too, and its
/// strict misses in a row ([`strict_misses_after`]). The run that brings
/// them to [`STRICT_MISSES_BEFORE_DRIFT`] retires the program
/// [`DRIFT_REASON`] at `by`'s word, in the same write. A program no longer
/// filed counts nothing.
///
/// # Errors
///
/// Storage errors.
pub fn record_workflow_run(
    vault: &Vault,
    id: EntityId,
    outcome: &RunOutcome,
    by: EntityId,
    at: u64,
) -> Result<()> {
    let Some(filed) = workflow(vault, id)? else {
        return Ok(());
    };
    let key = (site_key(&filed.site), id);
    vault.with_write_txn_grouped(|wtxn| {
        let Some(mut record) = WORKFLOWS.get(&vault.store, wtxn, &key)? else {
            return Ok(());
        };
        record.runs = record.runs.saturating_add(1);
        if !outcome.done {
            record.failures = record.failures.saturating_add(1);
            index_failure_in_txn(vault, wtxn, &record)?;
        }
        let recent = if outcome.done {
            RecentOutcome::Pass
        } else {
            RecentOutcome::Miss
        };
        push_recent(&mut record.recent, recent, at);
        record.last_run_at = Some(at);
        record.strict_misses = strict_misses_after(record.strict_misses, outcome);
        if record.strict_misses >= STRICT_MISSES_BEFORE_DRIFT {
            retire_in_txn(vault, wtxn, record, by, Some(DRIFT_REASON), at)?;
            return Ok(());
        }
        WORKFLOWS.put(vault, wtxn, &key, &record)
    })
}

/// Takes the program filed under `id` out of the library, at `by`'s word at
/// `at`, for `reason`, and keeps the record it had with them. A later solved
/// run that passes both checks files it afresh, with no runs.
///
/// # Errors
///
/// Storage errors.
pub fn retire_workflow(
    vault: &Vault,
    id: EntityId,
    by: EntityId,
    reason: Option<&str>,
    at: u64,
) -> Result<Retired> {
    let Some(filed) = workflow(vault, id)? else {
        return Ok(Retired::NotFiled);
    };
    let key = (site_key(&filed.site), id);
    vault.with_write_txn_grouped(|wtxn| {
        let Some(record) = WORKFLOWS.get(&vault.store, wtxn, &key)? else {
            return Ok(Retired::NotFiled);
        };
        if RETIRE_FILER_ONLY && !record.filed_by.is(by) {
            return Ok(Retired::NotFiler);
        }
        let trace = retire_in_txn(vault, wtxn, record, by, reason, at)?;
        Ok(Retired::Taken(Box::new(trace.record)))
    })
}

/// Takes `record` out of the library in `wtxn`, at `by`'s word at `at`, for
/// `reason`, and keeps it with them: the one retire, for `library.retire`
/// and for a successor's filing alike.
fn retire_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    record: WorkflowRecord,
    by: EntityId,
    reason: Option<&str>,
    at: u64,
) -> Result<RetiredWorkflow> {
    let id = record.id;
    WORKFLOWS.delete(&vault.store, wtxn, &(site_key(&record.site), id))?;
    index_retire_in_txn(vault, wtxn, &record)?;
    let trace = RetiredWorkflow {
        record,
        retired_by: LibraryActor::Actor(by),
        retired_at: at,
        reason: reason
            .map(str::trim)
            .filter(|reason| !reason.is_empty())
            .map(str::to_owned),
    };
    RETIRED.put(vault, wtxn, &id, &trace)?;
    Ok(trace)
}

/// Where `id` leads in `txn`: the program filed under it while it is live;
/// once it retired [`superseded_reason`], its successor, down the chain to
/// the live one; [`WorkflowResolution::Retired`] where the chain ends at a
/// retire with no successor (or comes back on itself); and
/// [`WorkflowResolution::Missing`] where no program was filed under it.
///
/// # Errors
///
/// Storage errors, or a library row that cannot be read.
pub fn resolve_workflow_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
) -> Result<WorkflowResolution> {
    let Some(mut trace) = RETIRED.get(&vault.store, txn, id)? else {
        let live = WORKFLOWS.scan(&vault.store, txn)?;
        if live.iter().any(|(_, record)| record.id == *id) {
            return Ok(WorkflowResolution::Active { id: *id });
        }
        return Ok(WorkflowResolution::Missing);
    };
    let mut seen = vec![*id];
    while let Some(next) = trace.reason.as_deref().and_then(superseded_by) {
        if seen.contains(&next) {
            break;
        }
        let key = (site_key(&trace.record.site), next);
        if WORKFLOWS.get(&vault.store, txn, &key)?.is_some() {
            return Ok(WorkflowResolution::Active { id: next });
        }
        let Some(retired) = RETIRED.get(&vault.store, txn, &next)? else {
            break;
        };
        seen.push(next);
        trace = retired;
    }
    Ok(WorkflowResolution::Retired {
        id: trace.record.id,
        reason: trace.reason,
    })
}

/// What the retire of `id` kept, if one took it out.
///
/// # Errors
///
/// Storage errors.
pub fn retired_workflow(vault: &Vault, id: EntityId) -> Result<Option<RetiredWorkflow>> {
    let rtxn = vault.store.env.read_txn()?;
    RETIRED.get(&vault.store, &rtxn, &id)
}

/// What retires took out of the library for `site`, the newest first.
///
/// # Errors
///
/// Storage errors.
pub fn retired_workflows(vault: &Vault, site: &str) -> Result<Vec<RetiredWorkflow>> {
    let rtxn = vault.store.env.read_txn()?;
    let mut retired: Vec<RetiredWorkflow> = RETIRED
        .scan(&vault.store, &rtxn)?
        .into_iter()
        .map(|(_, trace)| trace)
        .filter(|trace| trace.record.site == site)
        .collect();
    retired.sort_by_key(|trace| Reverse(trace.retired_at));
    Ok(retired)
}
