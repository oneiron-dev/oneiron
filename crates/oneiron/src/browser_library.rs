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
//! `find` reads a program by its task type too (CUA E4): the node and tree
//! version its subgoal placed at when it was filed, in the canonical
//! `node_id@tree_version` form ([`type_filter`]), matched exactly.
//!
//! Erasing an actor keeps every row and its times and states
//! [`ERASED_CALL_IDENTITY`] for whose run filed a program and whose word
//! retired it (FIX 812's rule, as call receipts keep it).

use oneiron_browser::{
    BatchStopCause, LibraryCard, LibraryRunMode, RecentCounts, RetiredCard, RunOutcome,
    SupersedeOutcome, SupersedeRefusal, WorkflowProgram, WorkflowProof,
};
use serde::{Deserialize, Serialize};

use crate::entity_id::EntityId;
use crate::learning::TypeRef;
use crate::receipt::ERASED_CALL_IDENTITY;
use crate::side_table::{self, Named, SideTable};
use crate::task_type::TaskTypeRef;

mod erase;
mod evidence;
mod index;
mod records;
pub(crate) use erase::{erase_retired_actor_in_txn, erase_workflow_actor_in_txn};
pub use evidence::{
    CANDIDATE_DOMAIN, FiledScope, SOLVED_CAPTURE_VERSION, SOLVED_GROUP_DOMAIN, SOLVED_RUN_DOMAIN,
    SOLVED_RUN_PREDICATE, SOLVED_SCOPE_DOMAIN, SavedBrowserCaller, ScopedSolvedGroupKey,
    SolvedCaptureGap, SolvedCaptureReceipt, SolvedGroupKey, SolvedRunCapture, SolvedRunEvidence,
    SolvedRunScope, SolvedSource,
};
pub use index::{
    DirtySolvedGroup, FailureLineage, Page, PageCursor, ProgramFailureRef, ProgramSeen,
    SOLVED_PAGE, dirty_solved_groups, mark_group_clean, mark_program_seen_in_txn, program_seen,
    programs_with_failures, solved_group_coverage, solved_runs_in_group,
};
pub(crate) use index::{
    erase_authority_actor_in_txn, erase_dirty_actor_in_txn, index_capture_in_txn,
    invalidate_solved_source_in_txn,
};
pub use records::{
    file_workflow, record_workflow_run, resolve_workflow_in_txn, retire_workflow, retired_workflow,
    retired_workflows, site_workflows, supersedes_refusal, workflow,
};

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
    /// The solved group its filing's caller filed it in (CUA E8a): none
    /// for a filing with no caller scope. No card shows it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filed_scope: Option<FiledScope>,
}

impl WorkflowRecord {
    /// The program as a planner reads it.
    #[must_use]
    pub fn card(&self) -> LibraryCard {
        LibraryCard {
            workflow: self.id.to_hex(),
            site: self.site.clone(),
            subgoal: self.program.subgoal.clone(),
            type_ref: TaskTypeRef::from(&self.type_ref).wire_form(),
            params: self.program.params.clone(),
            secret_params: self.program.secret_params.clone(),
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

/// A `find` filter that is not a task type's `node_id@tree_version`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("type_ref {0:?} names no task type: it is written node_id@tree_version")]
pub struct TypeFilterMalformed(pub String);

/// The task type a `find` filter names (CUA E4), read once from the
/// canonical form [`TaskTypeRef::wire_form`] writes and each card's
/// `type_ref` carries.
///
/// # Errors
///
/// [`TypeFilterMalformed`], naming `wire`, when it is not that form.
pub fn type_filter(wire: &str) -> std::result::Result<TaskTypeRef, TypeFilterMalformed> {
    TaskTypeRef::parse_wire(wire).map_err(|_| TypeFilterMalformed(wire.to_owned()))
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
