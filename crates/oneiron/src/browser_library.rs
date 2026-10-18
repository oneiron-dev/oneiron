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
//! Erasing an actor keeps every row and its times and states
//! [`ERASED_CALL_IDENTITY`] for whose run filed a program and whose word
//! retired it (FIX 812's rule, as call receipts keep it).

use std::cmp::Reverse;

use oneiron_browser::{LibraryCard, RetiredCard, WorkflowProgram, WorkflowProof};
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
        }
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

/// Files `program` for `site` once both checks passed (`proof`), from
/// `by`'s run, stamped with the task type the host's placement ladder
/// (`decisions`) reads; without one the rule rung reads alone. The same
/// program filed again keeps its id and its runs and takes the new proof.
///
/// # Errors
///
/// Storage errors.
pub fn file_workflow(
    vault: &Vault,
    by: EntityId,
    site: &str,
    program: &WorkflowProgram,
    proof: &WorkflowProof,
    at: u64,
    decisions: Option<&PlacementDecisions<'_>>,
) -> Result<EntityId> {
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
    let record = match filed {
        Some(record) => WorkflowRecord {
            type_ref,
            proof: proof.clone(),
            filed_by: LibraryActor::Actor(by),
            filed_at: at,
            ..record
        },
        None => WorkflowRecord {
            id: EntityId::now(),
            site: site.to_owned(),
            program: program.clone(),
            type_ref,
            proof: proof.clone(),
            filed_by: LibraryActor::Actor(by),
            filed_at: at,
            runs: 0,
            failures: 0,
            last_run_at: None,
        },
    };
    vault.with_write_txn_grouped(|wtxn| {
        WORKFLOWS.put(vault, wtxn, &(site_key(site), record.id), &record)
    })?;
    Ok(record.id)
}

/// Counts one library run of `id`, and whether it met its postcondition.
/// A program no longer filed counts nothing.
///
/// # Errors
///
/// Storage errors.
pub fn record_workflow_run(vault: &Vault, id: EntityId, met: bool, at: u64) -> Result<()> {
    let Some(filed) = workflow(vault, id)? else {
        return Ok(());
    };
    let key = (site_key(&filed.site), id);
    vault.with_write_txn_grouped(|wtxn| {
        let Some(mut record) = WORKFLOWS.get(&vault.store, wtxn, &key)? else {
            return Ok(());
        };
        record.runs = record.runs.saturating_add(1);
        if !met {
            record.failures = record.failures.saturating_add(1);
        }
        record.last_run_at = Some(at);
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
        WORKFLOWS.delete(&vault.store, wtxn, &key)?;
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
        Ok(Retired::Taken(Box::new(trace.record)))
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

/// Erasing `actor`: every program its run filed, and every retire at its
/// word, keeps its row, its times and its reason, and states
/// [`ERASED_CALL_IDENTITY`] for the actor. One-way, in the erase's own
/// transaction. An id whose entity is no actor scans nothing.
///
/// # Errors
///
/// Storage errors, or a library row that cannot be read.
pub(crate) fn erase_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> Result<()> {
    if let Some(raw) = vault.get_raw_in(wtxn, actor)?
        && let Some(header) = crate::batch::EntityMetadataHeader::parse(&raw)
        && !matches!(
            header.entity_type,
            crate::registry::ENTITY_TYPE_PERSON
                | crate::registry::ENTITY_TYPE_MACHINE
                | crate::registry::ENTITY_TYPE_AGENT_DEF
        )
    {
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
