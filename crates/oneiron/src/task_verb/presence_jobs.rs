//! The attempt/run-tree job projection the TASKS presence reads: the whole
//! ledger's for the board, one TASK's rows and their run-tree descendants for
//! a read by id (FIX 11970).

use std::collections::{BTreeMap, HashSet};

use crate::Vault;
use crate::attempt_queue::{
    AttemptCancelReceiptKind, AttemptQueue, AttemptRecord,
    SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD,
};
use crate::context_board::{CancelRejectionPathology, JobPresence, one_line_token};
use crate::error::Result;
use crate::memory::BRIDGE_OUTBOUND_ATTEMPT_KIND;
use crate::run_tree::{RunTreeNode, render_run_tree};

use super::highway_runner::workflow_try::bound_wrapper_job;
use super::presence_scan::{attempt_hex, superseded_attempt_ids};

/// The attempt/run-tree job projection, shared by the bounded board scan and
/// the direct-by-id path so both see identical job identity and ordering.
pub(super) struct JobBacklinks {
    /// Realizing jobs keyed by the hex TASK ref their attempt backlinks.
    pub(super) realizing: BTreeMap<String, Vec<JobPresence>>,
    /// Jobs that were bare from the start — no task backlink at all.
    pub(super) bare: Vec<JobPresence>,
}

pub(super) fn job_backlinks(vault: &Vault) -> Result<JobBacklinks> {
    let records = AttemptQueue::new(vault).list()?;
    let task_refs_by_attempt: BTreeMap<String, Option<String>> = records
        .iter()
        .map(|record| (attempt_hex(record.id), record.task_ref.clone()))
        .collect();
    let mut realizing: BTreeMap<String, Vec<JobPresence>> = BTreeMap::new();
    let mut bare = Vec::new();
    for_each_head_job(records, |node, job, superseded| {
        let backlink = task_refs_by_attempt.get(&node.attempt_id);
        match backlink {
            Some(Some(task_ref)) => realizing
                .entry(task_ref.clone())
                .or_default()
                .push(bound_wrapper_job(node, job, superseded)),
            _ if node.worker_kind == BRIDGE_OUTBOUND_ATTEMPT_KIND => {}
            _ => bare.push(job),
        }
    })?;
    Ok(JobBacklinks { realizing, bare })
}

/// [`job_backlinks`]' realizing jobs of the one TASK `task_hex`, read from its
/// rows and their run-tree descendants alone, so a read by id decodes no other
/// row of the ledger (FIX 11970). Rows are read in one snapshot, once.
pub(super) fn job_backlinks_for_task(vault: &Vault, task_hex: &str) -> Result<Vec<JobPresence>> {
    let records = {
        let txn = vault.store.env.read_txn()?;
        AttemptQueue::new(vault).task_subtree_in_txn(&txn, task_hex)?
    };
    let members: HashSet<String> = records
        .iter()
        .filter(|record| record.task_ref.as_deref() == Some(task_hex))
        .map(|record| attempt_hex(record.id))
        .collect();
    let mut jobs = Vec::new();
    for_each_head_job(records, |node, job, superseded| {
        if members.contains(&node.attempt_id) {
            jobs.push(bound_wrapper_job(node, job, superseded));
        }
    })?;
    Ok(jobs)
}

/// Renders `records` into their run tree and hands `visit`, in pre-order, each
/// node that reaches a board as a job, with the superseded ids it was judged by.
fn for_each_head_job(
    records: Vec<AttemptRecord>,
    mut visit: impl FnMut(&RunTreeNode, JobPresence, &HashSet<String>),
) -> Result<()> {
    let superseded: HashSet<String> = superseded_attempt_ids(&records)
        .into_iter()
        .map(attempt_hex)
        .collect();
    // ONE-1896 §1: the owner's own surface is where repeated refusal has to
    // land, so the signal is derived HERE, from the durable rows this scan
    // already read, and folded onto the job it belongs to.
    let pathology_by_attempt: BTreeMap<String, CancelRejectionPathology> = records
        .iter()
        .filter_map(|record| {
            cancel_rejection_pathology(record).map(|pathology| (attempt_hex(record.id), pathology))
        })
        .collect();
    // The tree renders from the rows this scan already read: one decode of
    // the ledger per board read, not two, and one snapshot (FIX 11318).
    let tree = render_run_tree(records)?;
    let mut nodes = Vec::new();
    collect_run_tree_nodes(&tree.roots, &mut nodes);
    for node in nodes {
        // Only retry-chain HEADS reach the board: a superseded try is replaced
        // work whose successor owns the realization. The run tree keeps every
        // try — nested under the one it replaces — as the forensic surface.
        if superseded.contains(&node.attempt_id) {
            continue;
        }
        let Some(job) = JobPresence::from_run_tree_node(node) else {
            continue;
        };
        let job = job.with_cancel_pathology(pathology_by_attempt.get(&node.attempt_id).cloned());
        visit(node, job, &superseded);
    }
    Ok(())
}

/// The owner-visible refusal signal for one ATTEMPT, or `None` when the worker
/// is behaving.
///
/// Only crossing [`SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD`] surfaces
/// anything: one "not yet, I am mid-commit" is a legitimate answer and must not
/// clutter the board. A settled row is silent too — an attempt that refused and
/// then finished is history, not something an owner can still act on.
fn cancel_rejection_pathology(record: &AttemptRecord) -> Option<CancelRejectionPathology> {
    if record.state.is_terminal() || !record.soft_cancel_pathology() {
        return None;
    }
    // The worker's OWN last word on why it will not stop, so the owner is not
    // acting on a bare number. Status first, refusal reason second: the status
    // is what the protocol asks a refusing worker to report.
    let last_status = record
        .cancel_receipts()
        .iter()
        .rev()
        .find(|receipt| receipt.kind == AttemptCancelReceiptKind::SoftRejected)
        .and_then(|receipt| {
            receipt
                .status
                .clone()
                .or_else(|| receipt.reason.clone())
                .map(|line| one_line_token(&line))
        });
    Some(CancelRejectionPathology {
        attempt_id: attempt_hex(record.id),
        rejections: record.cancel_pressure().rejections,
        threshold: SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD,
        last_status,
    })
}

/// Every node of `nodes` and their subtrees, in pre-order, on a heap stack
/// (FIX 10603).
fn collect_run_tree_nodes<'a>(nodes: &'a [RunTreeNode], out: &mut Vec<&'a RunTreeNode>) {
    let mut pending: Vec<&RunTreeNode> = nodes.iter().rev().collect();
    while let Some(node) = pending.pop() {
        out.push(node);
        pending.extend(node.children.iter().rev());
    }
}
