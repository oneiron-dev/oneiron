//! The replay library's store (OF-598; EIRI-ARCH-0002 "The replay library"):
//! solved browser runs, filed per site as parameterised programs with the
//! evidence of their two checks. The run's browser session runs the checks
//! (the solved page, then one no-model replay); this store files only what
//! passed both, and counts each live library run after.
//!
//! A filed program is the library's `code` TASK: one subgoal's parameterised
//! program, stamped with its task type (OF-543). It is kept here rather than
//! as a TASK entity, so filing it routes no work; running it is the browser
//! verb `self.browser.library.run`.

use std::cmp::Reverse;

use oneiron_browser::{LibraryCard, WorkflowProgram, WorkflowProof};
use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::learning::TypeRef;
use crate::side_table::{self, Named, SideTable};
use crate::task_type::{PlacementDecisions, PlacementRequest, place_type_ref};

/// The library's programs. Key: the site's BLAKE3 hash, then the program's id.
const WORKFLOWS: SideTable<([u8; 32], EntityId), WorkflowRecord, Named> =
    SideTable::new(&side_table::BROWSER_WORKFLOW);

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
    pub filed_by: EntityId,
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
    let filed = site_workflows(vault, site, None)?
        .into_iter()
        .find(|record| serde_json::to_value(&record.program).ok() == same);
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
            filed_by: by,
            filed_at: at,
            ..record
        },
        None => WorkflowRecord {
            id: EntityId::now(),
            site: site.to_owned(),
            program: program.clone(),
            type_ref,
            proof: proof.clone(),
            filed_by: by,
            filed_at: at,
            runs: 0,
            failures: 0,
            last_run_at: None,
        },
    };
    vault.with_write_txn_grouped(|wtxn| {
        WORKFLOWS.put(&vault.store, wtxn, &(site_key(site), record.id), &record)
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
        WORKFLOWS.put(&vault.store, wtxn, &key, &record)
    })
}
