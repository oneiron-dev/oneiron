//! Read-only run tree projection over generic JobQueue rows.
//!
//! This module intentionally stays a data adapter: it does not own queue
//! lifecycle transitions, live progress events, pause/resume, or intervention
//! APIs.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::dreamer_runner::{DREAMER_RUNNER_JOB_KIND, decode_dreamer_job_payload};
use crate::error::Result;
use crate::job_queue::{JobQueue, JobRecord, JobState, job_record_order};
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
    pub children: Vec<RunTreeNode>,
}

/// Surface lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunTreeStatus {
    Queued,
    Running,
    Completed,
    Failed,
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
        render_run_tree(self.queue.list()?)
    }

    /// Renders persisted rows for one run id into deterministic roots and
    /// children.
    pub fn read_run(&self, run_id: &str) -> Result<RunTree> {
        render_run_tree(self.queue.list_run(run_id)?)
    }
}

/// Renders queue rows into a deterministic tree without mutating storage.
pub fn render_run_tree(mut records: Vec<JobRecord>) -> Result<RunTree> {
    records.sort_by(job_record_order);

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

    for leftover in remaining_nodes(children_by_parent, &emitted) {
        if emitted.contains(&leftover.node.job_id) {
            continue;
        }
        if let Some(parent_id) = leftover.node.parent_id.clone() {
            repairs.push(RunTreeRepair::ParentCycle {
                job_id: leftover.node.job_id.clone(),
                parent_id,
            });
        }
        rendered_roots.push(leftover.node);
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

fn flat_node(record: JobRecord) -> Result<FlatRunTreeNode> {
    let metadata = job_metadata(&record)?;
    let node = RunTreeNode {
        job_id: job_id_hex(&record),
        run_id: record.run_id,
        parent_id: metadata.parent_id,
        worker_kind: metadata.worker_kind,
        status: RunTreeStatus::from(record.state),
        timestamps: RunTreeTimestamps {
            created_at: record.created_at,
            updated_at: record.updated_at,
        },
        failure: record.last_error.map(|reason| RunTreeFailure { reason }),
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

fn remaining_nodes(
    children_by_parent: BTreeMap<String, Vec<FlatRunTreeNode>>,
    emitted: &HashSet<String>,
) -> Vec<FlatRunTreeNode> {
    let mut nodes = children_by_parent
        .into_values()
        .flatten()
        .filter(|node| !emitted.contains(&node.node.job_id))
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.node.job_id.cmp(&right.node.job_id))
    });
    nodes
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

impl From<JobState> for RunTreeStatus {
    fn from(state: JobState) -> Self {
        match state {
            JobState::Queued => Self::Queued,
            JobState::Leased => Self::Running,
            JobState::Completed => Self::Completed,
            JobState::Failed => Self::Failed,
        }
    }
}

#[cfg(test)]
mod tests {
    use rmpv::Value;

    use crate::dreamer_runner::{DreamerRunnerStore, EnqueueDreamerJob, EnqueueDreamerJobOutcome};
    use crate::job_queue::{
        ClaimJob, ClaimOutcome, CompleteJob, CompleteOutcome, FailJob, FailOutcome,
    };
    use crate::{Result, Vault, VaultConfig};

    use super::{RunTreeAdapter, RunTreeRepair, RunTreeStatus};

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

        assert_eq!(root_node.children[1].job_id, hex(right.job.id));
        assert_eq!(root_node.children[1].worker_kind, "right-subagent");

        Ok(())
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

    fn hex(id: crate::JobId) -> String {
        crate::types::bytes_to_hex_lower(id.as_bytes())
    }
}
