//! Run tree projection and control adapter over generic AttemptQueue rows.
//!
//! Lifecycle transitions stay in [`AttemptQueue`]. This module renders queue rows
//! and their lifecycle/operator events into a deterministic tree surface.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

use crate::Vault;
use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
use crate::attempt_queue::{
    AttemptEvent, AttemptInterventionKind, AttemptQueue, AttemptRecord, AttemptState,
    attempt_record_order,
};
use crate::consult_ladder::{A2aBaseTaskState, A2aTaskProjection, OneironA2aExtensions};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

/// Renderable run tree for dashboard/read APIs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTree {
    pub roots: Vec<RunTreeNode>,
    pub repairs: Vec<RunTreeRepair>,
}

/// One renderable attempt node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunTreeNode {
    #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
    pub attempt_id: String,
    pub run_id: Option<String>,
    pub parent_id: Option<String>,
    pub worker_kind: String,
    /// The dispatched agent's label for `agent.dispatch` attempts (decoded from
    /// the payload snapshot; tolerant — a malformed inner input renders as
    /// `None`). Additive and elided when absent, so serialized trees stay
    /// wire-compatible in both directions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    pub status: RunTreeStatus,
    pub timestamps: RunTreeTimestamps,
    pub failure: Option<RunTreeFailure>,
    pub events: Vec<RunTreeEvent>,
    pub children: Vec<RunTreeNode>,
}

/// Surface lifecycle status.
///
/// A waiting [`AttemptState::Scheduled`] try maps onto the existing `Paused`
/// token — deferred, not eligible to run now — which the Context Board already
/// projects as `TaskBoardStatus::Scheduled`. No readiness field or new variant
/// is added here.
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
        #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
        attempt_id: String,
        missing_parent_id: String,
    },
    ParentCycle {
        #[serde(rename = "job_id")] // wire key pinned pre-rename (ONE-1714)
        attempt_id: String,
        parent_id: String,
    },
}

/// Read adapter over the runtime attempt queue.
pub struct RunTreeAdapter<'a> {
    queue: AttemptQueue<'a>,
}

impl<'a> RunTreeAdapter<'a> {
    /// Opens a run-tree read adapter over an already-open vault.
    #[must_use]
    pub fn new(vault: &'a Vault) -> Self {
        Self {
            queue: AttemptQueue::new(vault),
        }
    }

    /// Renders all persisted attempt rows into deterministic roots and children.
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
pub fn render_run_tree(mut records: Vec<AttemptRecord>) -> Result<RunTree> {
    records.sort_by(attempt_record_order);
    render_run_tree_presorted(records)
}

fn render_run_tree_presorted(records: Vec<AttemptRecord>) -> Result<RunTree> {
    let present: BTreeSet<String> = records.iter().map(attempt_id_hex).collect();
    let mut repairs = Vec::new();
    let mut roots = Vec::new();
    let mut children_by_parent: BTreeMap<String, Vec<FlatRunTreeNode>> = BTreeMap::new();

    for record in records {
        let flat = flat_node(record)?;
        match flat.node.parent_id.as_deref() {
            Some(parent_id) if parent_id == flat.node.attempt_id => {
                repairs.push(RunTreeRepair::ParentCycle {
                    attempt_id: flat.node.attempt_id.clone(),
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
                    attempt_id: flat.node.attempt_id.clone(),
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

/// Projects one row's lifecycle onto the surface status.
///
/// READINESS, not the bare enum, separates runnable-now from deferred. A
/// pre-ONE-1795 row decodes as [`AttemptState::Queued`] carrying only
/// `backoff_until`, and the queue's readiness instant keeps that claim time, so
/// the claim loop holds it back exactly like an [`AttemptState::Scheduled`]
/// row. Rendering it `Queued` would tell every read surface it is runnable now
/// while the queue refuses to hand it out. A row queued by this build never
/// carries a readiness instant — claim and lease-timeout requeue both clear
/// both spellings — so only deferred rows take this arm.
fn run_tree_status(record: &AttemptRecord) -> RunTreeStatus {
    let deferred = record.scheduled_at.or(record.backoff_until).is_some();
    match record.state {
        AttemptState::Queued if deferred => RunTreeStatus::Paused,
        state => RunTreeStatus::from(state),
    }
}

fn flat_node(mut record: AttemptRecord) -> Result<FlatRunTreeNode> {
    let metadata = attempt_metadata(&record);
    let state = record.state;
    let status = run_tree_status(&record);
    let attempt_id = attempt_id_hex(&record);
    let events = run_tree_events(
        record.created_at,
        record.updated_at,
        record.attempt_count,
        record.claimed_at,
        std::mem::take(&mut record.events),
        state,
    )?;
    let node = RunTreeNode {
        attempt_id,
        run_id: record.run_id,
        parent_id: metadata.parent_id,
        worker_kind: metadata.worker_kind,
        agent_id: metadata.agent_id,
        status,
        timestamps: RunTreeTimestamps {
            created_at: record.created_at,
            updated_at: record.updated_at,
        },
        failure: match state {
            AttemptState::Failed => record.last_error.map(|reason| RunTreeFailure { reason }),
            AttemptState::Queued
            | AttemptState::Leased
            | AttemptState::Paused
            | AttemptState::Scheduled
            | AttemptState::Landing
            | AttemptState::Completed
            | AttemptState::Cancelled => None,
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
    let attempt_id = flat.node.attempt_id.clone();
    if !emitted.insert(attempt_id.clone()) {
        return flat.node;
    }

    path.push(attempt_id.clone());
    let mut node = flat.node;
    let children = children_by_parent.remove(&attempt_id).unwrap_or_default();
    node.children = children
        .into_iter()
        .filter_map(|child| {
            if path.contains(&child.node.attempt_id) {
                repairs.push(RunTreeRepair::ParentCycle {
                    attempt_id: child.node.attempt_id,
                    parent_id: attempt_id.clone(),
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
        .filter(|node| !emitted.contains(&node.node.attempt_id))
        .min_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.node.attempt_id.cmp(&right.node.attempt_id))
        })
        .cloned()
}

struct AttemptMetadata {
    parent_id: Option<String>,
    worker_kind: String,
    agent_id: Option<String>,
}

fn attempt_metadata(record: &AttemptRecord) -> AttemptMetadata {
    // A retry's parent is the try it replaces — an explicit row link that
    // outranks the Dreamer payload's spawn lineage, so a retried try renders as
    // a child of the failed one rather than as a second root.
    let retry_parent = record
        .retry_of
        .map(|source| bytes_to_hex_lower(source.as_bytes()));

    if record.kind == DREAMER_RUNNER_ATTEMPT_KIND {
        // Tolerant read (extends the inner-input tolerance below to the OUTER
        // envelope): a malformed dreamer payload — reachable via the public
        // `AttemptQueue::enqueue` API, which accepts an arbitrary `kind` and
        // `payload` — must degrade this row to a bare job rather than abort the
        // whole tree render and poison `tasks.check`/`expand` for unrelated
        // tasks.
        let Ok(payload) = decode_dreamer_attempt_payload(&record.payload) else {
            return AttemptMetadata {
                parent_id: retry_parent,
                worker_kind: record.kind.clone(),
                agent_id: None,
            };
        };
        // Tolerant read: the payload envelope already decoded, so a malformed
        // inner agent-dispatch input must not kill the whole tree render —
        // the node degrades to `agent_id: None`.
        let agent_id = if payload.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE {
            decode_agent_dispatch_input(&payload.input)
                .ok()
                .map(|input| input.definition.agent_id)
        } else {
            None
        };
        return AttemptMetadata {
            parent_id: retry_parent.or_else(|| {
                payload
                    .parent_attempt
                    .map(|parent| bytes_to_hex_lower(parent.as_bytes()))
            }),
            worker_kind: payload.attempt_type,
            agent_id,
        };
    }

    AttemptMetadata {
        parent_id: retry_parent,
        worker_kind: record.kind.clone(),
        agent_id: None,
    }
}

fn attempt_id_hex(record: &AttemptRecord) -> String {
    bytes_to_hex_lower(record.id.as_bytes())
}

fn run_tree_events(
    created_at: u64,
    updated_at: u64,
    attempt_count: u32,
    claimed_at: Option<u64>,
    stored_events: Vec<AttemptEvent>,
    state: AttemptState,
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

fn operator_event(event: AttemptEvent, sequence_offset: u64) -> Result<RunTreeEvent> {
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

fn status_event_kind(state: AttemptState) -> Option<RunTreeEventKind> {
    match state {
        // A scheduled try has not run yet; `Created` is its only lifecycle
        // event, exactly as for a queued one.
        AttemptState::Queued | AttemptState::Scheduled => None,
        // A landing row is still under its claim; the trigger provenance rides
        // the durable cancel receipts and the A2A projection, not a synthetic
        // run-tree event, so the six-token event vocabulary stays closed.
        AttemptState::Leased | AttemptState::Landing => Some(RunTreeEventKind::Claimed),
        AttemptState::Paused => Some(RunTreeEventKind::Paused),
        AttemptState::Completed => Some(RunTreeEventKind::Completed),
        AttemptState::Failed => Some(RunTreeEventKind::Failed),
        AttemptState::Cancelled => Some(RunTreeEventKind::Cancelled),
    }
}

impl From<AttemptState> for RunTreeStatus {
    fn from(state: AttemptState) -> Self {
        match state {
            AttemptState::Queued => Self::Queued,
            // A landing attempt is STILL RUNNING: it holds its lease and is
            // doing bounded finishing work. It is emphatically not `Completed`
            // — nothing was delivered — and not `Cancelled` — nothing was
            // killed. The trigger provenance rides
            // [`project_attempt_to_a2a`] and the durable receipts rather than a
            // seventh status token, so no read surface has to learn a new axis
            // to keep telling live work from settled work.
            AttemptState::Leased | AttemptState::Landing => Self::Running,
            // Deferred until its scheduled instant: the same "not eligible to
            // run now" axis the board already renders as Scheduled.
            AttemptState::Paused | AttemptState::Scheduled => Self::Paused,
            AttemptState::Completed => Self::Completed,
            AttemptState::Failed => Self::Failed,
            AttemptState::Cancelled => Self::Cancelled,
        }
    }
}

/// Projects one ATTEMPT row onto A2A task vocabulary, preserving the two-rung
/// graceful-cancel distinctions A2A itself cannot express.
///
/// The invariant this exists to hold: a LANDING attempt projects as `working`
/// carrying `cancel_mode = "landing"`, never as `completed` and never as
/// `cancelled`. A peer reading only the base state sees honest live work; a
/// peer reading the extensions can tell an accepted landing from a refusal,
/// from a designed stop, and from a hard kill.
#[must_use]
pub fn project_attempt_to_a2a(record: &AttemptRecord) -> A2aTaskProjection {
    let mut extensions = OneironA2aExtensions {
        cancel_rejections: record.cancel_pressure().rejections,
        resume_point: record
            .resume_point()
            .map(|resume_point| resume_point.marker.clone()),
        ..OneironA2aExtensions::default()
    };
    if let Some(landing) = record.landing() {
        extensions.landing_trigger = Some(landing.trigger.as_str().to_owned());
    }
    let base = match record.state {
        AttemptState::Queued | AttemptState::Scheduled | AttemptState::Leased => {
            A2aBaseTaskState::Working
        }
        AttemptState::Paused => A2aBaseTaskState::InputRequired,
        AttemptState::Landing => {
            extensions.cancel_mode = Some(ATTEMPT_A2A_CANCEL_MODE_LANDING.to_owned());
            A2aBaseTaskState::Working
        }
        AttemptState::Completed => A2aBaseTaskState::Completed,
        AttemptState::Failed => A2aBaseTaskState::Failed,
        AttemptState::Cancelled => A2aBaseTaskState::Cancelled,
    };
    if let Some(cancellation) = record.cancellation() {
        extensions.cancel_mode = Some(cancellation.mode.as_str().to_owned());
        if let Some(trigger) = cancellation.trigger {
            extensions.landing_trigger = Some(trigger.as_str().to_owned());
        }
    } else if base == A2aBaseTaskState::Working
        && extensions.cancel_mode.is_none()
        && record.cancel_pressure().requests > 0
    {
        // Asked but not yet settled: refusal outranks a bare outstanding ask,
        // because a peer needs to know the worker ANSWERED and said no.
        extensions.cancel_mode = Some(if extensions.cancel_rejections > 0 {
            ATTEMPT_A2A_CANCEL_MODE_REJECTED.to_owned()
        } else {
            ATTEMPT_A2A_CANCEL_MODE_REQUESTED.to_owned()
        });
    }
    A2aTaskProjection {
        id: attempt_id_hex(record),
        state: base,
        extensions,
    }
}

/// Wire tokens for [`OneironA2aExtensions::cancel_mode`] that have no durable
/// [`crate::attempt_queue::CancelMode`] behind them because the attempt has not
/// settled yet.
const ATTEMPT_A2A_CANCEL_MODE_LANDING: &str = "landing";
const ATTEMPT_A2A_CANCEL_MODE_REQUESTED: &str = "requested";
const ATTEMPT_A2A_CANCEL_MODE_REJECTED: &str = "rejected";

impl From<AttemptInterventionKind> for RunTreeEventKind {
    fn from(kind: AttemptInterventionKind) -> Self {
        match kind {
            AttemptInterventionKind::Interrupt => Self::Interrupted,
            AttemptInterventionKind::Pause => Self::Paused,
            AttemptInterventionKind::Resume => Self::Resumed,
            AttemptInterventionKind::Cancel => Self::Cancelled,
        }
    }
}

#[cfg(test)]
mod tests;
