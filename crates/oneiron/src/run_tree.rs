//! Run tree projection and control adapter over generic JobQueue rows.
//!
//! Lifecycle transitions stay in [`JobQueue`]. This module renders queue rows
//! and their lifecycle/operator events into a deterministic tree surface.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::dreamer_runner::{DREAMER_RUNNER_JOB_KIND, decode_dreamer_job_payload};
use crate::error::{Error, Result};
use crate::job_queue::{
    JobEvent, JobInterventionKind, JobQueue, JobRecord, JobState, job_record_order,
};
use crate::types::bytes_to_hex_lower;

/// Renderable run tree for dashboard/read APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTree {
    pub roots: Vec<RunTreeNode>,
    pub repairs: Vec<RunTreeRepair>,
}

/// One renderable job node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeNode {
    pub job_id: String,
    pub run_id: Option<String>,
    pub parent_id: Option<String>,
    pub worker_kind: String,
    pub status: RunTreeStatus,
    pub timestamps: RunTreeTimestamps,
    pub failure: Option<RunTreeFailure>,
    pub events: Vec<RunTreeEvent>,
    pub children: Vec<RunTreeNode>,
}

/// Surface lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTreeStatus {
    Queued,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

/// Node timestamps copied from the backing queue row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeTimestamps {
    pub created_at: u64,
    pub updated_at: u64,
}

/// Summarized failure state for display and API reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeFailure {
    pub reason: String,
}

/// Lifecycle/operator event for display and API reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeEvent {
    pub sequence: u64,
    pub at: u64,
    pub actor: String,
    pub kind: RunTreeEventKind,
    pub note: Option<String>,
}

/// Surface lifecycle/operator event kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTreeEventKind {
    Created,
    Claimed,
    Paused,
    Resumed,
    Completed,
    Failed,
    Cancelled,
    Interrupted,
}

/// Non-mutating repairs applied while rendering a tree from rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RunTreeRepair {
    MissingParent {
        job_id: String,
        missing_parent_id: String,
    },
    ParentCycle {
        job_id: String,
        parent_id: String,
    },
}

/// Read adapter over the runtime job queue.
pub struct RunTreeAdapter<'a> {
    queue: JobQueue<'a>,
}

impl<'a> RunTreeAdapter<'a> {
    /// Opens a run-tree read adapter over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            queue: JobQueue::new(vault),
        }
    }

    /// Renders all persisted job rows into deterministic roots and children.
    pub fn read(&self) -> Result<RunTree> {
        render_run_tree_presorted(self.queue.list()?)
    }

    /// Renders persisted rows for one run id into deterministic roots and
    /// children.
    pub fn read_run(&self, run_id: &str) -> Result<RunTree> {
        render_run_tree_presorted(self.queue.list_run(run_id)?)
    }
}

/// Renders queue rows into a deterministic tree without mutating storage.
pub fn render_run_tree(mut records: Vec<JobRecord>) -> Result<RunTree> {
    records.sort_by(job_record_order);
    render_run_tree_presorted(records)
}

fn render_run_tree_presorted(records: Vec<JobRecord>) -> Result<RunTree> {
    let present: BTreeSet<String> = records.iter().map(job_id_hex).collect();
    let mut repairs = Vec::new();
    let mut roots = Vec::new();
    let mut children_by_parent: BTreeMap<String, Vec<FlatRunTreeNode>> = BTreeMap::new();

    for record in records {
        let flat = flat_node(record)?;
        match flat.node.parent_id.as_deref() {
            Some(parent_id) if parent_id == flat.node.job_id => {
                repairs.push(RunTreeRepair::ParentCycle {
                    job_id: flat.node.job_id.clone(),
                    parent_id: parent_id.to_owned(),
                });
                roots.push(flat);
            }
            Some(parent_id) if present.contains(parent_id) => {
                children_by_parent
                    .entry(parent_id.to_owned())
                    .or_default()
                    .push(flat);
            }
            Some(parent_id) => {
                repairs.push(RunTreeRepair::MissingParent {
                    job_id: flat.node.job_id.clone(),
                    missing_parent_id: parent_id.to_owned(),
                });
                roots.push(flat);
            }
            None => roots.push(flat),
        }
    }

    let mut emitted = HashSet::new();
    let mut rendered_roots = Vec::new();
    for root in roots {
        rendered_roots.push(attach_children(
            root,
            &mut children_by_parent,
            &mut emitted,
            &mut repairs,
            &mut Vec::new(),
        ));
    }

    while let Some(leftover) = next_remaining_node(&children_by_parent, &emitted) {
        rendered_roots.push(attach_children(
            leftover,
            &mut children_by_parent,
            &mut emitted,
            &mut repairs,
            &mut Vec::new(),
        ));
    }

    Ok(RunTree {
        roots: rendered_roots,
        repairs,
    })
}

#[derive(Debug, Clone)]
struct FlatRunTreeNode {
    node: RunTreeNode,
    created_at: u64,
}

const RUN_TREE_RUNTIME_ACTOR: &str = "runtime";

fn flat_node(mut record: JobRecord) -> Result<FlatRunTreeNode> {
    let metadata = job_metadata(&record)?;
    let state = record.state;
    let job_id = job_id_hex(&record);
    let events = run_tree_events(
        record.created_at,
        record.updated_at,
        record.attempt_count,
        record.claimed_at,
        std::mem::take(&mut record.events),
        state,
    )?;
    let node = RunTreeNode {
        job_id,
        run_id: record.run_id,
        parent_id: metadata.parent_id,
        worker_kind: metadata.worker_kind,
        status: RunTreeStatus::from(state),
        timestamps: RunTreeTimestamps {
            created_at: record.created_at,
            updated_at: record.updated_at,
        },
        failure: match state {
            JobState::Failed => record.last_error.map(|reason| RunTreeFailure { reason }),
            JobState::Queued
            | JobState::Leased
            | JobState::Paused
            | JobState::Completed
            | JobState::Cancelled => None,
        },
        events,
        children: Vec::new(),
    };

    Ok(FlatRunTreeNode {
        created_at: node.timestamps.created_at,
        node,
    })
}

fn attach_children(
    flat: FlatRunTreeNode,
    children_by_parent: &mut BTreeMap<String, Vec<FlatRunTreeNode>>,
    emitted: &mut HashSet<String>,
    repairs: &mut Vec<RunTreeRepair>,
    path: &mut Vec<String>,
) -> RunTreeNode {
    let job_id = flat.node.job_id.clone();
    if !emitted.insert(job_id.clone()) {
        return flat.node;
    }

    path.push(job_id.clone());
    let mut node = flat.node;
    let children = children_by_parent.remove(&job_id).unwrap_or_default();
    node.children = children
        .into_iter()
        .filter_map(|child| {
            if path.contains(&child.node.job_id) {
                repairs.push(RunTreeRepair::ParentCycle {
                    job_id: child.node.job_id,
                    parent_id: job_id.clone(),
                });
                return None;
            }
            Some(attach_children(
                child,
                children_by_parent,
                emitted,
                repairs,
                path,
            ))
        })
        .collect();
    path.pop();
    node
}

fn next_remaining_node(
    children_by_parent: &BTreeMap<String, Vec<FlatRunTreeNode>>,
    emitted: &HashSet<String>,
) -> Option<FlatRunTreeNode> {
    children_by_parent
        .values()
        .flat_map(|nodes| nodes.iter())
        .filter(|node| !emitted.contains(&node.node.job_id))
        .min_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.node.job_id.cmp(&right.node.job_id))
        })
        .cloned()
}

struct JobMetadata {
    parent_id: Option<String>,
    worker_kind: String,
}

fn job_metadata(record: &JobRecord) -> Result<JobMetadata> {
    if record.kind == DREAMER_RUNNER_JOB_KIND {
        let payload = decode_dreamer_job_payload(&record.payload)?;
        return Ok(JobMetadata {
            parent_id: payload
                .parent_job
                .map(|parent| bytes_to_hex_lower(parent.as_bytes())),
            worker_kind: payload.job_type,
        });
    }

    Ok(JobMetadata {
        parent_id: None,
        worker_kind: record.kind.clone(),
    })
}

fn job_id_hex(record: &JobRecord) -> String {
    bytes_to_hex_lower(record.id.as_bytes())
}

fn run_tree_events(
    created_at: u64,
    updated_at: u64,
    attempt_count: u32,
    claimed_at: Option<u64>,
    stored_events: Vec<JobEvent>,
    state: JobState,
) -> Result<Vec<RunTreeEvent>> {
    let has_claim = attempt_count > 0;
    let mut events = Vec::with_capacity(stored_events.len() + 2 + usize::from(has_claim));
    events.push(lifecycle_event(0, created_at, RunTreeEventKind::Created));
    if has_claim {
        // Pre-claim-timestamp rows cannot recover the historical lease time;
        // keep their projected claimed event stable instead of using updated_at.
        events.push(lifecycle_event(
            1,
            claimed_at.unwrap_or(created_at),
            RunTreeEventKind::Claimed,
        ));
    }
    let sequence_offset = u64::from(has_claim);
    for event in stored_events {
        events.push(operator_event(event, sequence_offset)?);
    }

    if let Some(kind) = status_event_kind(state)
        && !events.iter().any(|event| event.kind == kind)
    {
        let sequence = events
            .iter()
            .map(|event| event.sequence)
            .max()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow("run-tree event sequence"))?;
        events.push(lifecycle_event(sequence, updated_at, kind));
    }

    Ok(events)
}

fn operator_event(event: JobEvent, sequence_offset: u64) -> Result<RunTreeEvent> {
    Ok(RunTreeEvent {
        sequence: event
            .sequence
            .checked_add(sequence_offset)
            .ok_or(Error::ArithmeticOverflow("run-tree event sequence"))?,
        at: event.at,
        actor: event.actor,
        kind: RunTreeEventKind::from(event.kind),
        note: event.note,
    })
}

fn lifecycle_event(sequence: u64, at: u64, kind: RunTreeEventKind) -> RunTreeEvent {
    RunTreeEvent {
        sequence,
        at,
        actor: RUN_TREE_RUNTIME_ACTOR.to_owned(),
        kind,
        note: None,
    }
}

fn status_event_kind(state: JobState) -> Option<RunTreeEventKind> {
    match state {
        JobState::Queued => None,
        JobState::Leased => Some(RunTreeEventKind::Claimed),
        JobState::Paused => Some(RunTreeEventKind::Paused),
        JobState::Completed => Some(RunTreeEventKind::Completed),
        JobState::Failed => Some(RunTreeEventKind::Failed),
        JobState::Cancelled => Some(RunTreeEventKind::Cancelled),
    }
}

impl From<JobState> for RunTreeStatus {
    fn from(state: JobState) -> Self {
        match state {
            JobState::Queued => Self::Queued,
            JobState::Leased => Self::Running,
            JobState::Paused => Self::Paused,
            JobState::Completed => Self::Completed,
            JobState::Failed => Self::Failed,
            JobState::Cancelled => Self::Cancelled,
        }
    }
}

impl From<JobInterventionKind> for RunTreeEventKind {
    fn from(kind: JobInterventionKind) -> Self {
        match kind {
            JobInterventionKind::Interrupt => Self::Interrupted,
            JobInterventionKind::Pause => Self::Paused,
            JobInterventionKind::Resume => Self::Resumed,
            JobInterventionKind::Cancel => Self::Cancelled,
        }
    }
}

#[cfg(test)]
mod tests;
