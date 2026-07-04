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
    stored_events: Vec<JobEvent>,
    state: JobState,
) -> Result<Vec<RunTreeEvent>> {
    let mut events = Vec::with_capacity(stored_events.len() + 2);
    events.push(lifecycle_event(0, created_at, RunTreeEventKind::Created));
    events.extend(stored_events.into_iter().map(RunTreeEvent::from));

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

impl From<JobEvent> for RunTreeEvent {
    fn from(event: JobEvent) -> Self {
        Self {
            sequence: event.sequence,
            at: event.at,
            actor: event.actor,
            kind: RunTreeEventKind::from(event.kind),
            note: event.note,
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
mod tests {
    use rmpv::Value;

    use crate::dreamer_runner::{
        DREAMER_RUNNER_JOB_KIND, DreamerJobPayload, DreamerRunnerStore, EnqueueDreamerJob,
        EnqueueDreamerJobOutcome, encode_dreamer_job_payload,
    };
    use crate::job_queue::{
        ClaimJob, ClaimOutcome, CompleteJob, CompleteOutcome, FailJob, FailOutcome, InterveneJob,
        JobEvent, JobInterventionKind, JobRecord, JobState, RetryJob, RetryOutcome,
    };
    use crate::{Error, Result, Vault, VaultConfig};

    use super::{
        RunTreeAdapter, RunTreeEventKind, RunTreeRepair, RunTreeStatus, render_run_tree,
        run_tree_events,
    };

    fn open_vault() -> (tempfile::TempDir, Vault) {
        crate::test_util::open_test_vault_with(VaultConfig::device())
    }

    #[test]
    fn run_tree_renders_nested_subagent_jobs_deterministically() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);

        let root = enqueue(&runner, "orchestrator", None, 10, "run-a")?;
        let left = enqueue(&runner, "left-subagent", Some(root.job.id), 20, "run-a")?;
        let right = enqueue(&runner, "right-subagent", Some(root.job.id), 30, "run-a")?;
        let leaf = enqueue(&runner, "leaf-worker", Some(left.job.id), 40, "run-a")?;

        complete_next(&vault, root.job.id, 50)?;
        complete_next(&vault, left.job.id, 60)?;
        complete_next(&vault, right.job.id, 70)?;
        fail_next(&vault, leaf.job.id, 80, "left branch failed")?;

        let tree = RunTreeAdapter::new(&vault).read_run("run-a")?;

        assert!(tree.repairs.is_empty());
        assert_eq!(tree.roots.len(), 1);
        let root_node = &tree.roots[0];
        assert_eq!(root_node.job_id, hex(root.job.id));
        assert_eq!(root_node.run_id.as_deref(), Some("run-a"));
        assert_eq!(root_node.parent_id, None);
        assert_eq!(root_node.worker_kind, "orchestrator");
        assert_eq!(root_node.status, RunTreeStatus::Completed);
        assert_eq!(
            event_kinds(root_node),
            vec![RunTreeEventKind::Created, RunTreeEventKind::Completed]
        );
        assert_eq!(root_node.children.len(), 2);

        assert_eq!(root_node.children[0].job_id, hex(left.job.id));
        assert_eq!(root_node.children[0].worker_kind, "left-subagent");
        assert_eq!(root_node.children[0].children.len(), 1);
        assert_eq!(root_node.children[0].children[0].job_id, hex(leaf.job.id));
        assert_eq!(
            root_node.children[0].children[0]
                .failure
                .as_ref()
                .map(|failure| failure.reason.as_str()),
            Some("left branch failed")
        );
        assert_eq!(
            root_node.children[0].children[0].status,
            RunTreeStatus::Failed
        );
        assert_eq!(
            event_kinds(&root_node.children[0].children[0]),
            vec![RunTreeEventKind::Created, RunTreeEventKind::Failed]
        );

        assert_eq!(root_node.children[1].job_id, hex(right.job.id));
        assert_eq!(root_node.children[1].worker_kind, "right-subagent");

        Ok(())
    }

    #[test]
    fn run_tree_event_stream_reports_lifecycle_statuses() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let running = enqueue(&runner, "running-subagent", None, 10, "run-lifecycle")?;
        let completed = enqueue(&runner, "completed-subagent", None, 20, "run-lifecycle")?;
        let failed = enqueue(&runner, "failed-subagent", None, 30, "run-lifecycle")?;
        let queue = crate::JobQueue::new(&vault);

        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
            lease_owner: "stream-worker".to_owned(),
            now: 40,
        })?
        else {
            panic!("expected running claim");
        };
        assert_eq!(claimed.id, running.job.id);
        complete_next(&vault, completed.job.id, 50)?;
        fail_next(&vault, failed.job.id, 60, "terminal failure")?;

        let tree = RunTreeAdapter::new(&vault).read_run("run-lifecycle")?;

        assert_eq!(tree.roots.len(), 3);
        assert_eq!(tree.roots[0].job_id, hex(running.job.id));
        assert_eq!(tree.roots[0].status, RunTreeStatus::Running);
        assert_eq!(
            event_kinds(&tree.roots[0]),
            vec![RunTreeEventKind::Created, RunTreeEventKind::Claimed]
        );
        assert_eq!(tree.roots[0].events[0].sequence, 0);
        assert_eq!(tree.roots[0].events[0].at, 10);
        assert_eq!(tree.roots[0].events[1].sequence, 1);
        assert_eq!(tree.roots[0].events[1].at, 40);

        assert_eq!(tree.roots[1].job_id, hex(completed.job.id));
        assert_eq!(tree.roots[1].status, RunTreeStatus::Completed);
        assert_eq!(
            event_kinds(&tree.roots[1]),
            vec![RunTreeEventKind::Created, RunTreeEventKind::Completed]
        );
        assert_eq!(tree.roots[1].events[1].at, 50);

        assert_eq!(tree.roots[2].job_id, hex(failed.job.id));
        assert_eq!(tree.roots[2].status, RunTreeStatus::Failed);
        assert_eq!(
            event_kinds(&tree.roots[2]),
            vec![RunTreeEventKind::Created, RunTreeEventKind::Failed]
        );
        assert_eq!(tree.roots[2].events[1].at, 60);

        Ok(())
    }

    #[test]
    fn run_tree_event_sequence_overflow_fails_closed() {
        let events = vec![JobEvent {
            sequence: u64::MAX,
            at: 20,
            actor: "dashboard".to_owned(),
            kind: JobInterventionKind::Pause,
            note: None,
        }];

        let result = run_tree_events(10, 30, events, JobState::Completed);

        assert!(matches!(
            result,
            Err(Error::ArithmeticOverflow("run-tree event sequence"))
        ));
    }

    #[test]
    fn run_tree_promotes_missing_parent_to_repaired_root() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);

        let missing_parent = enqueue(&runner, "missing-parent", None, 10, "run-b")?;
        let child = enqueue(
            &runner,
            "orphaned-subagent",
            Some(missing_parent.job.id),
            20,
            "run-b",
        )?;
        delete_job_record(&vault, missing_parent.job.id)?;

        let tree = RunTreeAdapter::new(&vault).read_run("run-b")?;

        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.roots[0].job_id, hex(child.job.id));
        assert_eq!(
            tree.roots[0].parent_id.as_deref(),
            Some(hex(missing_parent.job.id).as_str())
        );
        assert_eq!(
            tree.repairs,
            vec![RunTreeRepair::MissingParent {
                job_id: hex(child.job.id),
                missing_parent_id: hex(missing_parent.job.id),
            }]
        );

        Ok(())
    }

    #[test]
    fn run_tree_omits_retry_last_error_until_terminal_failure() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue(&runner, "retrying-subagent", None, 10, "run-retry")?;
        let queue = crate::JobQueue::new(&vault);

        let ClaimOutcome::Claimed(claimed) = queue.claim(ClaimJob {
            lease_owner: "retry-worker".to_owned(),
            now: 20,
        })?
        else {
            panic!("expected claim");
        };
        assert_eq!(claimed.id, queued.job.id);
        let RetryOutcome::Retried(_) = queue.retry(RetryJob {
            id: claimed.id,
            lease_owner: "retry-worker".to_owned(),
            attempt_count: claimed.attempt_count,
            backoff_until: 40,
            last_error: Some("rate limited".to_owned()),
            now: 30,
        })?;

        let tree = RunTreeAdapter::new(&vault).read_run("run-retry")?;

        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.roots[0].status, RunTreeStatus::Queued);
        assert_eq!(tree.roots[0].failure, None);

        Ok(())
    }

    #[test]
    fn run_tree_projects_intervention_events_and_states() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let paused = enqueue(&runner, "paused-subagent", None, 10, "run-intervene")?;
        let cancelled = enqueue(&runner, "cancelled-subagent", None, 20, "run-intervene")?;
        let queue = crate::JobQueue::new(&vault);

        queue.intervene(InterveneJob {
            id: paused.job.id,
            kind: JobInterventionKind::Pause,
            actor: "dashboard".to_owned(),
            note: Some("hold branch".to_owned()),
            now: 30,
        })?;
        queue.intervene(InterveneJob {
            id: cancelled.job.id,
            kind: JobInterventionKind::Cancel,
            actor: "dashboard".to_owned(),
            note: None,
            now: 40,
        })?;

        let tree = RunTreeAdapter::new(&vault).read_run("run-intervene")?;

        assert_eq!(tree.roots.len(), 2);
        assert_eq!(tree.roots[0].job_id, hex(paused.job.id));
        assert_eq!(tree.roots[0].status, RunTreeStatus::Paused);
        assert_eq!(
            event_kinds(&tree.roots[0]),
            vec![RunTreeEventKind::Created, RunTreeEventKind::Paused]
        );
        assert_eq!(tree.roots[0].events[1].sequence, 1);
        assert_eq!(tree.roots[0].events[1].actor, "dashboard");
        assert_eq!(tree.roots[0].events[1].note.as_deref(), Some("hold branch"));
        assert_eq!(tree.roots[1].job_id, hex(cancelled.job.id));
        assert_eq!(tree.roots[1].status, RunTreeStatus::Cancelled);
        assert_eq!(
            event_kinds(&tree.roots[1]),
            vec![RunTreeEventKind::Created, RunTreeEventKind::Cancelled]
        );

        Ok(())
    }

    #[test]
    fn run_tree_fails_closed_when_runtime_job_table_is_unavailable() -> Result<()> {
        let (_dir, vault) = open_vault();
        let runner = DreamerRunnerStore::new(&vault);
        let queued = enqueue(&runner, "corrupt-subagent", None, 10, "run-corrupt")?;

        let mut wtxn = vault.store.env.write_txn()?;
        vault
            .store
            .job_records
            .put(&mut wtxn, queued.job.id.as_bytes(), b"not a job record")?;
        wtxn.commit()?;

        assert!(
            RunTreeAdapter::new(&vault).read_run("run-corrupt").is_err(),
            "run-tree reads must fail closed when a runtime job row cannot be decoded"
        );

        Ok(())
    }

    #[test]
    fn run_tree_preserves_descendants_when_repairing_rootless_cycle() -> Result<()> {
        let a = fixed_job_id(0x11);
        let b = fixed_job_id(0x22);
        let c = fixed_job_id(0x33);

        let tree = render_run_tree(vec![
            dreamer_record(a, "cycle-a", Some(b), 10, "run-cycle")?,
            dreamer_record(b, "cycle-b", Some(a), 20, "run-cycle")?,
            dreamer_record(c, "cycle-child", Some(a), 30, "run-cycle")?,
        ])?;

        assert_eq!(
            tree.repairs,
            vec![RunTreeRepair::ParentCycle {
                job_id: hex(a),
                parent_id: hex(b),
            }]
        );
        assert_eq!(tree.roots.len(), 1);
        assert_eq!(tree.roots[0].job_id, hex(a));
        assert_eq!(tree.roots[0].parent_id.as_deref(), Some(hex(b).as_str()));
        assert_eq!(tree.roots[0].children.len(), 2);
        assert_eq!(tree.roots[0].children[0].job_id, hex(b));
        assert!(tree.roots[0].children[0].children.is_empty());
        assert_eq!(tree.roots[0].children[1].job_id, hex(c));

        Ok(())
    }

    fn enqueue(
        runner: &DreamerRunnerStore<'_>,
        job_type: &str,
        parent_job: Option<crate::JobId>,
        now: u64,
        run_id: &str,
    ) -> Result<crate::DreamerJobStatus> {
        match runner.enqueue(EnqueueDreamerJob {
            job_type: job_type.to_owned(),
            input: Value::from(format!("input:{job_type}")),
            parent_job,
            dedupe_key: None,
            run_id: Some(run_id.to_owned()),
            now,
        })? {
            EnqueueDreamerJobOutcome::Enqueued(status)
            | EnqueueDreamerJobOutcome::Existing(status) => Ok(status),
        }
    }

    fn complete_next(vault: &Vault, expected_id: crate::JobId, now: u64) -> Result<()> {
        let queue = crate::JobQueue::new(vault);
        let ClaimOutcome::Claimed(job) = queue.claim(ClaimJob {
            lease_owner: "test-worker".to_owned(),
            now,
        })?
        else {
            panic!("expected claim");
        };
        assert_eq!(job.id, expected_id);
        let CompleteOutcome::Completed(_) = queue.complete(CompleteJob {
            id: expected_id,
            lease_owner: "test-worker".to_owned(),
            attempt_count: job.attempt_count,
            now,
        })?
        else {
            panic!("expected completion");
        };
        Ok(())
    }

    fn fail_next(vault: &Vault, expected_id: crate::JobId, now: u64, reason: &str) -> Result<()> {
        let queue = crate::JobQueue::new(vault);
        let ClaimOutcome::Claimed(job) = queue.claim(ClaimJob {
            lease_owner: "test-worker".to_owned(),
            now,
        })?
        else {
            panic!("expected claim");
        };
        assert_eq!(job.id, expected_id);
        let FailOutcome::Failed(_) = queue.fail(FailJob {
            id: expected_id,
            lease_owner: "test-worker".to_owned(),
            attempt_count: job.attempt_count,
            reason: reason.to_owned(),
            now,
        })?
        else {
            panic!("expected failure");
        };
        Ok(())
    }

    fn delete_job_record(vault: &Vault, id: crate::JobId) -> Result<()> {
        let mut wtxn = vault.store.env.write_txn()?;
        vault.store.job_records.delete(&mut wtxn, id.as_bytes())?;
        wtxn.commit()?;
        Ok(())
    }

    fn event_kinds(node: &super::RunTreeNode) -> Vec<RunTreeEventKind> {
        node.events.iter().map(|event| event.kind).collect()
    }

    fn dreamer_record(
        id: crate::JobId,
        job_type: &str,
        parent_job: Option<crate::JobId>,
        created_at: u64,
        run_id: &str,
    ) -> Result<JobRecord> {
        Ok(JobRecord {
            id,
            kind: DREAMER_RUNNER_JOB_KIND.to_owned(),
            payload: encode_dreamer_job_payload(&DreamerJobPayload {
                job_type: job_type.to_owned(),
                input: Value::from(format!("input:{job_type}")),
                parent_job,
            })?,
            state: JobState::Queued,
            lease_owner: None,
            attempt_count: 0,
            backoff_until: None,
            last_error: None,
            run_id: Some(run_id.to_owned()),
            dedupe_key: None,
            created_at,
            updated_at: created_at,
            events: Vec::new(),
        })
    }

    fn fixed_job_id(byte: u8) -> crate::JobId {
        crate::JobId::from_bytes(&[byte; 16]).expect("valid fixed job id")
    }

    fn hex(id: crate::JobId) -> String {
        crate::types::bytes_to_hex_lower(id.as_bytes())
    }
}
