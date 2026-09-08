//! Deterministic run-tree build from attempt rows: flatten, repair, attach, events.

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::agent_dispatch::{AGENT_DISPATCH_ATTEMPT_TYPE, decode_agent_dispatch_input};
use crate::attempt_queue::{AttemptEvent, AttemptRecord, AttemptState, attempt_record_order};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::entity_id::bytes_to_hex_lower;
use crate::error::{Error, Result};

use super::types::{
    RunTree, RunTreeEvent, RunTreeEventKind, RunTreeFailure, RunTreeNode, RunTreeRepair,
    RunTreeStatus, RunTreeTimestamps,
};

/// Renders queue rows into a deterministic tree without mutating storage.
pub fn render_run_tree(mut records: Vec<AttemptRecord>) -> Result<RunTree> {
    records.sort_by(attempt_record_order);
    render_run_tree_presorted(records)
}

pub(super) fn render_run_tree_presorted(records: Vec<AttemptRecord>) -> Result<RunTree> {
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
    let result_ref = record
        .result_ref
        .take()
        .map(crate::attempt_queue::AttemptResultRef::into_string);
    let events = run_tree_events(
        record.created_at,
        record.updated_at,
        record.attempt_count,
        record.claimed_at,
        std::mem::take(&mut record.events),
        state,
        result_ref.is_some(),
    )?;
    let node = RunTreeNode {
        attempt_id,
        run_id: record.run_id,
        parent_id: metadata.parent_id,
        worker_kind: metadata.worker_kind,
        agent_id: metadata.agent_id,
        status,
        result_ref,
        timestamps: RunTreeTimestamps {
            created_at: record.created_at,
            updated_at: record.updated_at,
        },
        // An abandoned row carries its stop reason in `last_error`, but this
        // field is the FAILURE summary and only `Failed` fills it: rendering
        // an abandonment's reason here would present a stop nobody diagnosed
        // as a diagnosed fault, and every read surface that folds on
        // `failure.is_some()` would then count it as one.
        failure: match state {
            AttemptState::Failed => record.last_error.map(|reason| RunTreeFailure { reason }),
            AttemptState::Queued
            | AttemptState::Leased
            | AttemptState::Paused
            | AttemptState::Scheduled
            | AttemptState::Landing
            | AttemptState::Completed
            | AttemptState::Cancelled
            | AttemptState::Abandoned => None,
        },
        events,
        children: Vec::new(),
        // Rendering reads durable attempt rows only. The breaker marker is
        // applied afterwards, by a caller holding the projection.
        gate_breaker_paused: false,
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

pub(super) fn attempt_id_hex(record: &AttemptRecord) -> String {
    bytes_to_hex_lower(record.id.as_bytes())
}

pub(super) fn run_tree_events(
    created_at: u64,
    updated_at: u64,
    attempt_count: u32,
    claimed_at: Option<u64>,
    stored_events: Vec<AttemptEvent>,
    state: AttemptState,
    has_result: bool,
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

    // A row that named a result says so before it says how it ended: the
    // artifact is durable first, and the settling event is what a reader
    // scans back from. Ordering them the other way would render a terminal
    // node whose last event claims work continued after it stopped.
    if has_result {
        push_lifecycle_event(&mut events, updated_at, RunTreeEventKind::ResultAttached)?;
    }
    if let Some(kind) = status_event_kind(state) {
        push_lifecycle_event(&mut events, updated_at, kind)?;
    }

    Ok(events)
}

/// Appends one synthesized lifecycle event, unless the stream already carries
/// that kind from a durable operator row. Cancellation must be the final event.
fn push_lifecycle_event(
    events: &mut Vec<RunTreeEvent>,
    at: u64,
    kind: RunTreeEventKind,
) -> Result<()> {
    let already_present = if kind == RunTreeEventKind::Cancelled {
        // Keep the operator's cancellation intact, but do not let it suppress
        // terminal truth after a synthesized result attachment. Only the
        // queue's Cancelled state requests this final lifecycle event.
        events.last().is_some_and(|event| event.kind == kind)
    } else {
        events.iter().any(|event| event.kind == kind)
    };
    if already_present {
        return Ok(());
    }
    let sequence = events
        .iter()
        .map(|event| event.sequence)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(Error::ArithmeticOverflow("run-tree event sequence"))?;
    events.push(lifecycle_event(sequence, at, kind));
    Ok(())
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
        AttemptState::Abandoned => Some(RunTreeEventKind::Abandoned),
    }
}
