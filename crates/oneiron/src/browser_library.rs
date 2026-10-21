//! The replay library's store (OF-598; EIRI-ARCH-0002 "The replay library"):
//! solved browser runs, filed per site as parameterised programs with the
//! evidence of their two checks. The run's browser session runs the checks
//! (the solved page, then one no-model replay); this store files only what
//! passed both, and counts each live library run after.
//!
//! A filed program is the library's `code` TASK: one subgoal's parameterised
//! program, stamped with its task type (OF-543). It is kept here rather than
//! as a TASK entity, so filing it routes no work; running it is the browser
//! verb `self.browser.library.run`, and `self.browser.library.retire` takes
//! it out, keeping the record it had with whose word, when and why;
//! `self.browser.library.retired` lists what retires took out for a site.
//!
//! One program is one record (CUA E1): the same bytes refile the same
//! record, and changed bytes that repair a program are a new record naming
//! it in `supersedes`, filed in the same write that retires the old one
//! `superseded:<new id>`. The retire chain is the lineage, which
//! [`resolve_workflow_in_txn`] follows to the live program. Each record
//! keeps its lineage's newest outcomes ([`RECENT_RUNS`]), which a successor
//! takes over, and its strict misses in a row, the
//! [`STRICT_MISSES_BEFORE_DRIFT`]th retiring it [`DRIFT_REASON`] in the same
//! write (CUA E2).
//!
//! Erasing an actor keeps every row and its times and states
//! [`ERASED_CALL_IDENTITY`] for whose run filed a program and whose word
//! retired it (FIX 812's rule, as call receipts keep it).

use std::cmp::Reverse;

use oneiron_browser::{
    BatchStopCause, LibraryCard, LibraryRunMode, RecentCounts, RetiredCard, RunOutcome,
    SupersedeOutcome, SupersedeRefusal, WorkflowProgram, WorkflowProof,
};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::batch::secret_scan::{admitted_from, named_tree};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::TypeRef;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::side_table::{self, Named, SideTable};
use crate::task_type::{PlacementDecisions, PlacementRequest, place_type_ref};

/// The library's programs. Key: the site's BLAKE3 hash, then the program's id.
const WORKFLOWS: SideTable<([u8; 32], EntityId), WorkflowRecord, Named> =
    SideTable::new(&side_table::BROWSER_WORKFLOW);

/// What each retire took out. Key: the program's id (a refile after a retire
/// takes a new one).
const RETIRED: SideTable<EntityId, RetiredWorkflow, Named> =
    SideTable::new(&side_table::BROWSER_WORKFLOW_RETIRED);

/// Whether only the caller whose run filed a program may retire it. A filed
/// program is the vault's: any caller the library serves may run or refile
/// it (a refile moves `filed_by`), so any may retire it too.
pub const RETIRE_FILER_ONLY: bool = false;

/// How many of a lineage's newest outcomes its card counts as recent (CUA
/// E1 "recent", CALLS row; Engine 10-21 23:4x): each record keeps the last
/// [`RECENT_RUNS`] library runs, passed or missed, and repairs of its
/// lineage, the oldest dropped past them, and a successor starts from its
/// predecessor's. A count of outcomes, not a time window, so a program run
/// rarely keeps its record.
pub const RECENT_RUNS: usize = 20;

/// The reason a retire records for a program a successor repaired is
/// `superseded:<the successor's id>` ([`superseded_reason`]).
const SUPERSEDED_PREFIX: &str = "superseded:";

/// The reason a retire records for a program that stopped working on its
/// site (its strict misses, counted by the run path).
pub const DRIFT_REASON: &str = "drift";

/// The strict misses in a row that retire a program [`DRIFT_REASON`] (CUA
/// E2 drift, CALLS row): the run that makes them this many retires it.
pub const STRICT_MISSES_BEFORE_DRIFT: u32 = 3;

/// A program's strict misses in a row after one run (CUA E2 drift, CALLS
/// row): a strict run that met its postcondition starts them again; a
/// strict run that stopped on an unmet postcondition or a missing locator
/// adds one. An assisted run, and a strict one that stopped for any other
/// cause (a clock, a press, a person's hold, a cut read, an ask-up, the
/// browser's own refusal, field text, no progress), leaves them: none of
/// those shows the program no longer fits its site.
#[must_use]
pub fn strict_misses_after(misses: u32, outcome: &RunOutcome) -> u32 {
    if outcome.mode != LibraryRunMode::Strict {
        return misses;
    }
    if outcome.done {
        return 0;
    }
    match outcome.stop_cause {
        Some(BatchStopCause::PostconditionUnmet | BatchStopCause::LocatorMissing) => {
            misses.saturating_add(1)
        }
        _ => misses,
    }
}

/// The reason a retire records for a program `successor` repaired.
#[must_use]
pub fn superseded_reason(successor: EntityId) -> String {
    format!("{SUPERSEDED_PREFIX}{}", successor.to_hex())
}

/// The successor a retire's `reason` names, when it is a
/// [`superseded_reason`].
fn superseded_by(reason: &str) -> Option<EntityId> {
    let successor = reason.strip_prefix(SUPERSEDED_PREFIX)?;
    EntityId::from_hex(successor).ok()
}

/// Whose word a library row records: an actor, or no one once that actor
/// was erased. It reads and writes as the actor's id, or as
/// [`ERASED_CALL_IDENTITY`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibraryActor {
    Actor(EntityId),
    Erased,
}

impl LibraryActor {
    /// Whether this is `actor`.
    #[must_use]
    pub fn is(self, actor: EntityId) -> bool {
        self == Self::Actor(actor)
    }
}

impl Serialize for LibraryActor {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Actor(id) => id.serialize(serializer),
            Self::Erased => serializer.serialize_str(ERASED_CALL_IDENTITY),
        }
    }
}

impl<'de> Deserialize<'de> for LibraryActor {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value == ERASED_CALL_IDENTITY {
            return Ok(Self::Erased);
        }
        EntityId::from_hex(&value)
            .map(Self::Actor)
            .map_err(serde::de::Error::custom)
    }
}

/// What one outcome of a program's lineage was: a library run that met its
/// postcondition, one that did not, or a repair that filed a successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecentOutcome {
    Pass,
    Miss,
    Repair,
}

/// One outcome of a program's lineage, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentRun {
    pub outcome: RecentOutcome,
    pub at: u64,
}

/// Adds `outcome` at `at` to a lineage's newest outcomes, keeping the last
/// [`RECENT_RUNS`].
fn push_recent(recent: &mut Vec<RecentRun>, outcome: RecentOutcome, at: u64) {
    recent.push(RecentRun { outcome, at });
    let over = recent.len().saturating_sub(RECENT_RUNS);
    recent.drain(..over);
}

/// One filed program, with its proof and its runs since.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowRecord {
    pub id: EntityId,
    pub site: String,
    pub program: WorkflowProgram,
    /// The task type its subgoal places at (OF-543).
    pub type_ref: TypeRef,
    pub proof: WorkflowProof,
    /// Whose run it was filed from, and when.
    pub filed_by: LibraryActor,
    pub filed_at: u64,
    pub runs: u32,
    /// Library runs that ended short of the postcondition.
    pub failures: u32,
    pub last_run_at: Option<u64>,
    /// The program this one repaired, live or retired when it was filed.
    pub supersedes: Option<EntityId>,
    /// Its lineage's newest outcomes, the oldest first: its own, after
    /// those of the programs it supersedes.
    pub recent: Vec<RecentRun>,
    /// Its strict runs in a row that missed ([`strict_misses_after`]).
    pub strict_misses: u32,
}

impl WorkflowRecord {
    /// The program as a planner reads it.
    #[must_use]
    pub fn card(&self) -> LibraryCard {
        LibraryCard {
            workflow: self.id.to_hex(),
            site: self.site.clone(),
            subgoal: self.program.subgoal.clone(),
            params: self.program.params.clone(),
            runs: self.runs,
            failures: self.failures,
            recent: recent_counts(&self.recent),
            held_out: self.proof.held_out,
            supersedes: self.supersedes.map(|id| id.to_hex()),
            seed: self.proof.seed.clone(),
            filed_at: self.filed_at,
            last_run_at: self.last_run_at,
            strict_misses: self.strict_misses,
        }
    }
}

/// A lineage's newest [`RECENT_RUNS`] outcomes, counted.
fn recent_counts(recent: &[RecentRun]) -> RecentCounts {
    let recent = &recent[recent.len().saturating_sub(RECENT_RUNS)..];
    let count = |outcome: RecentOutcome| {
        let counted = recent.iter().filter(|run| run.outcome == outcome).count();
        u32::try_from(counted).unwrap_or(u32::MAX)
    };
    RecentCounts {
        pass: count(RecentOutcome::Pass),
        miss: count(RecentOutcome::Miss),
        repair: count(RecentOutcome::Repair),
        of: u32::try_from(RECENT_RUNS).unwrap_or(u32::MAX),
    }
}

/// A program a retire took out: the record it had, whose word retired it,
/// when, and why.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetiredWorkflow {
    pub record: WorkflowRecord,
    pub retired_by: LibraryActor,
    pub retired_at: u64,
    /// The retiring caller's reason, when it gave one.
    pub reason: Option<String>,
}

impl RetiredWorkflow {
    /// The retired program as a planner reads it.
    #[must_use]
    pub fn card(&self) -> RetiredCard {
        RetiredCard {
            card: self.record.card(),
            retired_at: self.retired_at,
            reason: self.reason.clone(),
        }
    }
}

fn site_key(site: &str) -> [u8; 32] {
    *blake3::hash(site.as_bytes()).as_bytes()
}

/// The programs filed for `site` whose subgoal holds every word of
/// `subgoal`, ignoring case: the most runs that met their postcondition
/// first, then the newest.
///
/// # Errors
///
/// Storage errors.
pub fn site_workflows(
    vault: &Vault,
    site: &str,
    subgoal: Option<&str>,
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

/// What filing a program did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Filing {
    /// It is filed under `id`, and this is what became of the program its
    /// `supersedes` named, when it named one.
    Filed {
        id: EntityId,
        superseded: Option<SupersedeOutcome>,
    },
    /// Its `supersedes` link was refused; nothing was filed.
    Refused(SupersedeRefusal),
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

/// Files `program` for `site` once both checks passed (`proof`), from
/// `by`'s run, stamped with the task type the host's placement ladder
/// (`decisions`) reads; without one the rule rung reads alone. The same
/// program filed again keeps its id, its runs and its seed, and takes the
/// new proof; a `supersedes` link on it is dropped, as no repair.
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
) -> Result<Filing> {
    let same = serde_json::to_value(program).ok();
    // A filed program holds handles where this one may hold the secrets the
    // side-row wall lifted (OF-067); it is still the same program.
    let mut filed = None;
    for record in site_workflows(vault, site, None)? {
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
            let seed = record.proof.seed.take().or_else(|| proof.seed.clone());
            let record = WorkflowRecord {
                type_ref,
                proof: WorkflowProof {
                    seed,
                    ..proof.clone()
                },
                filed_by: LibraryActor::Actor(by),
                filed_at: at,
                ..record
            };
            WORKFLOWS.put(vault, wtxn, &(site_key(site), record.id), &record)?;
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
        let record = WorkflowRecord {
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
        };
        WORKFLOWS.put(vault, wtxn, &(site_key(site), id), &record)?;
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

/// What a retire did.
#[derive(Debug)]
pub enum Retired {
    /// The program left the library; this is the record it had.
    Taken(Box<WorkflowRecord>),
    /// No program is filed under the id.
    NotFiled,
    /// Another caller's run filed it, and [`RETIRE_FILER_ONLY`] holds.
    NotFiler,
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

/// Where a program's ref leads now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkflowResolution {
    /// The live program `id`: the one named, or its successor.
    Active { id: EntityId },
    /// The lineage ends at `id`, retired for `reason` with no successor.
    Retired {
        id: EntityId,
        reason: Option<String>,
    },
    /// No program was ever filed under the ref.
    Missing,
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

/// Whether `actor` names an entity that is no actor, so erasing it scans
/// nothing. An id with no record, or one whose header does not parse, still
/// scans.
fn is_no_actor(vault: &Vault, txn: &heed::RoTxn<'_>, actor: &EntityId) -> Result<bool> {
    if let Some(raw) = vault.get_raw_in(txn, actor)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
    {
        return Ok(!matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        ));
    }
    Ok(false)
}

/// Erasing `actor` from the filed programs: every program its run filed
/// keeps its row and its times, and states [`ERASED_CALL_IDENTITY`] for the
/// actor. One-way, in the erase's own transaction. An id whose entity is no
/// actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a library row that cannot be read.
pub(crate) fn erase_workflow_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if is_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut filed = Vec::new();
    for (key, mut record) in WORKFLOWS.scan(&vault.store, wtxn)? {
        if record.filed_by.is(*actor) {
            record.filed_by = LibraryActor::Erased;
            filed.push((key, record));
        }
    }
    for (key, record) in filed {
        WORKFLOWS.put(vault, wtxn, &key, &record)?;
    }
    Ok(())
}

/// Erasing `actor` from what retires took out: every retire at its word, and
/// every retired program its run filed, keeps its row, its times and its
/// reason, and states [`ERASED_CALL_IDENTITY`] for the actor. One-way, in the
/// erase's own transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a library row that cannot be read.
pub(crate) fn erase_retired_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if is_no_actor(vault, wtxn, actor)? {
        return Ok(());
    }
    let mut retired = Vec::new();
    for (id, mut trace) in RETIRED.scan(&vault.store, wtxn)? {
        let by = trace.retired_by.is(*actor);
        let filer = trace.record.filed_by.is(*actor);
        if by {
            trace.retired_by = LibraryActor::Erased;
        }
        if filer {
            trace.record.filed_by = LibraryActor::Erased;
        }
        if by || filer {
            retired.push((id, trace));
        }
    }
    for (id, trace) in retired {
        RETIRED.put(vault, wtxn, &id, &trace)?;
    }
    Ok(())
}
