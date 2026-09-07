use std::collections::{BTreeMap, HashSet};

use crate::Vault;
use crate::agent_dispatch::{
    AGENT_DISPATCH_ATTEMPT_TYPE, agent_dispatch_actor, decode_agent_dispatch_input,
};
use crate::attempt_queue::{
    AttemptCancelReceiptKind, AttemptId, AttemptQueue, AttemptRecord, AttemptState,
    SOFT_CANCEL_REJECTION_PATHOLOGY_THRESHOLD,
};
use crate::context_board::{
    CancelRejectionPathology, JobPresence, TaskBoardStatus, TaskIntentPresence, TasksSection,
    fold_up_status, one_line_token, task_is_acked, task_is_cancelled,
};
use crate::dreamer_runner::{DREAMER_RUNNER_ATTEMPT_KIND, decode_dreamer_attempt_payload};
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::habit::TaskRole;
use crate::memory::{BRIDGE_OUTBOUND_ATTEMPT_KIND, MemoryError, MemoryResult};
use crate::registry::ENTITY_TYPE_TASK;
use crate::run_tree::{RunTreeAdapter, RunTreeNode, RunTreeStatus};
use crate::unix_seconds_now;

use super::consult_result::CancelTargetState;
use super::follow_up::peer_handle_in;
use super::rate_limit::task_create_owner;
use super::route_receipts::TaskCancelTarget;
use super::terminal_state::{
    ConsultResultPresence, ConsultResultSummary, TaskExecutionState, TaskTerminalDisposition,
    TaskTerminalRecord, board_status_for_disposition,
};
use super::verb_kind::TaskAssignee;
use super::wire_decode::{
    task_entity_role, task_entity_role_in, task_verb_body, task_verb_body_in,
};

/// The attempt/run-tree job projection, shared by the bounded board scan and
/// the direct-by-id path so both see identical job identity and ordering.
struct JobBacklinks {
    /// Realizing jobs keyed by the hex TASK ref their attempt backlinks.
    realizing: BTreeMap<String, Vec<JobPresence>>,
    /// Jobs that were bare from the start — no task backlink at all.
    bare: Vec<JobPresence>,
}

fn job_backlinks(vault: &Vault) -> Result<JobBacklinks> {
    let records = AttemptQueue::new(vault).list()?;
    let task_refs_by_attempt: BTreeMap<String, Option<String>> = records
        .iter()
        .map(|record| (attempt_hex(record.id), record.task_ref.clone()))
        .collect();
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
    let tree = RunTreeAdapter::new(vault).read()?;
    let mut nodes = Vec::new();
    collect_run_tree_nodes(&tree.roots, &mut nodes);
    let mut realizing: BTreeMap<String, Vec<JobPresence>> = BTreeMap::new();
    let mut bare = Vec::new();
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
        match task_refs_by_attempt.get(&node.attempt_id) {
            Some(Some(task_ref)) => realizing.entry(task_ref.clone()).or_default().push(job),
            _ if node.worker_kind == BRIDGE_OUTBOUND_ATTEMPT_KIND => {}
            _ => bare.push(job),
        }
    }
    Ok(JobBacklinks { realizing, bare })
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

/// Number of TASK ids fetched per sanctioned `entities_by_type_page` call.
pub(super) const TASK_PRESENCE_PAGE_SIZE: usize = 256;
/// Maximum TASK entity ids inspected for ONE board assembly. It bounds WORK;
/// `TasksSection::RENDER_ROW_CAP` bounds tokens. A row beyond this prefix is
/// hidden from the collapsed board, never gone — `tasks.expand` / `tasks.ack`
/// still reach it by id.
pub(super) const TASK_PRESENCE_SCAN_CAP: usize = 4_096;

const _: () = assert!(TASK_PRESENCE_PAGE_SIZE > 0);
const _: () = assert!(TASK_PRESENCE_PAGE_SIZE <= TASK_PRESENCE_SCAN_CAP);
const _: () = assert!(TasksSection::RENDER_ROW_CAP < TASK_PRESENCE_SCAN_CAP);

#[derive(Debug)]
pub(super) struct TaskEntityPageScan {
    /// Bounded pages in type-index order; page boundaries are retained so
    /// `task_presence` opens exactly one render-state transaction per page.
    pub(super) pages: Vec<Vec<EntityId>>,
    pub(super) scanned_task_entities: usize,
    pub(super) source_exhausted: bool,
    /// Exclusive-after cursor / last processed TASK id from the scan loop.
    /// `None` when nothing was processed (scan_cap == 0 or empty source).
    /// Used under truncation to decide which realizing leftovers are provably
    /// in the scanned prefix (owner ≤ cursor → bare) vs still beyond the cap.
    pub(super) last_scanned_cursor: Option<EntityId>,
}

#[derive(Debug)]
pub(super) struct TaskPresenceSnapshot {
    pub(super) intents: Vec<TaskIntentPresence>,
    pub(super) bare_jobs: Vec<JobPresence>,
    pub(super) scanned_task_entities: usize,
    /// `false` means the scan cap stopped the walk before the TASK type index
    /// ran out, so the projection is a PREFIX, not a census. Load-bearing
    /// honesty: the renderer marks its overflow count as a lower bound.
    pub(super) source_exhausted: bool,
}

/// Pure bounded cursor loop over the sanctioned page primitive.
///
/// Production passes `Vault::entities_by_type_page`; tests pass a synthetic
/// pager and small explicit limits. Unpaged `entities_by_type` is never an
/// option here: it materializes the whole TASK index and returns
/// `IndexOverflow` past `MAX_TYPE_QUERY_RESULTS`, so a `.take(cap)` after it
/// would hard-fail before the iterator ever exists.
pub(super) fn scan_task_entity_pages<F>(
    page_size: usize,
    scan_cap: usize,
    mut fetch_page: F,
) -> Result<TaskEntityPageScan>
where
    F: FnMut(Option<&EntityId>, usize) -> Result<Vec<EntityId>>,
{
    // A zero page size would fetch nothing forever; clamping keeps forward
    // progress rather than reporting a false "exhausted".
    let page_size = page_size.max(1);
    let mut pages: Vec<Vec<EntityId>> = Vec::new();
    let mut after: Option<EntityId> = None;
    let mut scanned = 0_usize;
    let mut source_exhausted = false;
    let mut decided = false;

    while scanned < scan_cap {
        let remaining = scan_cap - scanned;
        // The extra row is a sentinel on the final capped page: fetching one
        // more than the budget is how "there is more" is learned without
        // spending scan work on it.
        let requested = page_size.min(remaining.saturating_add(1));
        let mut page = fetch_page(after.as_ref(), requested)?;
        if page.is_empty() {
            source_exhausted = true;
            decided = true;
            break;
        }

        let page_len = page.len();
        let process_count = page_len.min(remaining);
        let has_sentinel = page_len > process_count;
        // Defensive: nothing to process means the cursor cannot advance, so
        // stop rather than spin. The unprocessed rows still prove more exist.
        if process_count == 0 {
            decided = true;
            break;
        }
        page.truncate(process_count);

        // The cursor is an EXCLUSIVE lower bound in type-index order, so a
        // source that fails to advance it would replay rows forever; refusing
        // to continue keeps the walk finite and duplicate-free.
        let cursor = page.last().copied();
        if let (Some(previous), Some(next)) = (after, cursor)
            && next <= previous
        {
            decided = true;
            break;
        }

        scanned += process_count;
        after = cursor;
        pages.push(page);

        if has_sentinel {
            source_exhausted = false;
            decided = true;
            break;
        }
        if page_len < requested {
            source_exhausted = true;
            decided = true;
            break;
        }
    }

    if !decided {
        // The budget ran out on a page that exactly filled its request. One
        // bounded one-row probe past the cursor separates an exact census from
        // a lower bound, so a source that happens to end on the cap boundary
        // is not reported as truncated.
        source_exhausted = match after.as_ref() {
            Some(cursor) => fetch_page(Some(cursor), 1)?.is_empty(),
            // scan_cap == 0: nothing was inspected, so nothing is known.
            None => false,
        };
    }

    Ok(TaskEntityPageScan {
        pages,
        scanned_task_entities: scanned,
        source_exhausted,
        last_scanned_cursor: after,
    })
}

pub(super) fn task_presence(vault: &Vault) -> Result<TaskPresenceSnapshot> {
    task_presence_with_limits(vault, TASK_PRESENCE_PAGE_SIZE, TASK_PRESENCE_SCAN_CAP)
}

/// Testable body: production uses the constants above; local tests inject small
/// limits to force multi-page and scan-cap behaviour without a 100k-row vault.
pub(super) fn task_presence_with_limits(
    vault: &Vault,
    page_size: usize,
    scan_cap: usize,
) -> Result<TaskPresenceSnapshot> {
    let JobBacklinks {
        mut realizing,
        mut bare,
    } = job_backlinks(vault)?;
    let scan = scan_task_entity_pages(page_size, scan_cap, |after, limit| {
        vault.entities_by_type_page(ENTITY_TYPE_TASK, after, limit)
    })?;

    // Read-time clock: a consult past its deadline surfaces as expired from the
    // persisted deadline alone, so the failed row is never hidden behind
    // outbound (or reconciliation) availability.
    let now = unix_seconds_now();
    let mut intents = Vec::new();
    for page in &scan.pages {
        // ONE render-state/hydration transaction per page, replacing the two
        // state transactions per TASK the unpaged loop opened.
        let slots = {
            let rtxn = vault.store.env.read_txn()?;
            let mut slots = Vec::with_capacity(page.len());
            for &task_ref in page {
                // P2 F8 (board poisoning) covers the render-state read too: a
                // companion fact set that will not FOLD — an owner fork, a
                // malformed fact body, a fact re-pointed at a subject it does
                // not name — poisons exactly one row, never the section. Those
                // companions REPLICATE, so propagating here would let one
                // peer's corrupt row take `tasks.check` down on every node.
                //
                // The degrade is a SKIP, not a render with false bits: a task
                // whose facts cannot be read may really carry a Cancelled
                // fact, and rendering it as `cancelled: false` would resurrect
                // it on the active surface — cancel-wins holds under EVERY
                // merge order, including one that also forked the owner.
                // Nothing is lost by hiding the row: the skipped row's
                // realizing jobs re-emit as bare work below (P2 F7), and the
                // by-id door reads the same task the same way.
                //
                // Authority itself stays strict: `Vault::task_authority_state`
                // still refuses a forked proof, so the cancel / force-cancel
                // doors keep failing closed on exactly this task.
                let Ok(state) = TaskIntentPresence::render_state_in(vault, &rtxn, task_ref) else {
                    continue;
                };
                if state.cancelled {
                    continue;
                }
                let task_hex = task_ref.to_hex();
                let jobs = realizing.get(&task_hex).cloned().unwrap_or_default();
                // P2 F8 (board poisoning): one malformed TASK body must not
                // abort the whole board. A body that decodes badly — e.g. a
                // role byte carrying `subkind:"typed"` but missing the typed
                // fields — is skipped/degraded, never propagated as a hard
                // error that takes down `tasks.check`.
                match task_page_slot_in(vault, &rtxn, task_ref, &task_hex, jobs, state.acked, now) {
                    Ok(Some(slot)) => slots.push(slot),
                    Ok(None) | Err(_) => continue,
                }
            }
            slots
        };
        // Slot order is type-index order; resolving the deferred shapes here
        // keeps it that way while the page transaction is already closed.
        for slot in slots {
            let task_hex = slot.task_hex().to_owned();
            match slot.resolve(vault) {
                Ok(Some(intent)) => {
                    realizing.remove(&task_hex);
                    intents.push(intent);
                }
                Ok(None) | Err(_) => continue,
            }
        }
    }

    if scan.source_exhausted {
        // P2 F7 (dangling backlink): every live realizing job must render
        // exactly once. A backlink naming no surviving intent (deleted /
        // malformed / case-mismatched owner) is re-emitted as a bare job
        // instead of vanishing.
        bare.extend(realizing.into_values().flatten());
    } else {
        // Truncated scan: partition leftovers by owner id vs final cursor.
        // Pages walk contiguously in ascending exclusive-cursor order, so
        // every TASK index id ≤ the final cursor was processed. A leftover
        // backlink whose owner parses and is ≤ that cursor therefore names
        // either a nonexistent entity or a scanned-but-non-surviving owner
        // (cancelled / malformed / resolve-dropped) — provably dangling, and
        // the "renders exactly once" invariant requires it as bare. Owners
        // beyond the cursor are still "not scanned ≠ dangling" and stay
        // withheld. Cursor None (zero scanned) proves nothing → withhold all
        // parseable leftovers; unparseable owners can never appear in the
        // type index and always bare.
        for (task_hex, jobs) in realizing {
            let emit_as_bare = match EntityId::from_hex(&task_hex) {
                Err(_) => true,
                Ok(owner) => matches!(scan.last_scanned_cursor, Some(cursor) if owner <= cursor),
            };
            if emit_as_bare {
                bare.extend(jobs);
            }
        }
    }

    let snapshot = TaskPresenceSnapshot {
        intents,
        bare_jobs: bare,
        scanned_task_entities: scan.scanned_task_entities,
        source_exhausted: scan.source_exhausted,
    };
    debug_assert!(
        snapshot.scanned_task_entities <= scan_cap,
        "one board assembly inspects at most the scan cap"
    );
    Ok(snapshot)
}

/// Direct-by-id projection behind `tasks.expand` / `tasks.ack`.
///
/// It hydrates the requested TASK plus the jobs backlinked to it and NEVER
/// walks the TASK type index: the board's bounded prefix bounds what is SHOWN,
/// never what a typed read by id can reach. Hidden is one call away, not gone.
pub(super) fn task_presence_for_id(
    vault: &Vault,
    task_ref: EntityId,
) -> Result<Option<TaskIntentPresence>> {
    match task_is_cancelled(vault, task_ref) {
        Ok(false) => {}
        // Cancelled, or a companion fact set that will not fold at all (owner
        // fork / malformed fact body / a fact re-pointed at another subject).
        // Both leave the row off the surface, which is exactly what the board
        // scan does with the same task — the two doors must agree on a
        // poisoned companion, and unverifiable facts are never answered as
        // "not cancelled".
        Ok(true) | Err(_) => return Ok(None),
    }
    let task_hex = task_ref.to_hex();
    let jobs = job_backlinks(vault)?
        .realizing
        .remove(&task_hex)
        .unwrap_or_default();
    let Ok(acked) = task_is_acked(vault, task_ref) else {
        return Ok(None);
    };
    match task_intent_presence(vault, task_ref, &task_hex, jobs, acked, unix_seconds_now()) {
        Ok(found) => Ok(found),
        // A malformed body degrades to "not board-visible" here exactly as it
        // does in the board scan, so both doors agree on a poisoned row.
        Err(_) => Ok(None),
    }
}

/// One page row, split by whether it could be finished inside the page's
/// shared read transaction.
enum TaskPageSlot {
    /// Fully projected in-transaction: the typed TASK body path.
    Projected(TaskIntentPresence),
    /// A non-typed `Task`-role entity — connector-send subkind or role-only
    /// fold. Only `outbound`'s reader can tell them apart and it opens its own
    /// read transaction, so the row is finished after the page transaction
    /// closes, in its original slot position.
    Untyped {
        task_ref: EntityId,
        task_hex: String,
        jobs: Vec<JobPresence>,
        acked: bool,
    },
}

impl TaskPageSlot {
    fn task_hex(&self) -> &str {
        match self {
            Self::Projected(intent) => &intent.id,
            Self::Untyped { task_hex, .. } => task_hex,
        }
    }

    /// Finishes the row. Must run with no page transaction open.
    fn resolve(self, vault: &Vault) -> Result<Option<TaskIntentPresence>> {
        let (task_ref, task_hex, jobs, acked) = match self {
            Self::Projected(intent) => return Ok(Some(intent)),
            Self::Untyped {
                task_ref,
                task_hex,
                jobs,
                acked,
            } => (task_ref, task_hex, jobs, acked),
        };
        if let Some(task) = vault.connector_send_task(&task_ref)? {
            let status = fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Scheduled);
            return Ok(Some(TaskIntentPresence::from_connector_send_task_with_ack(
                &task, status, jobs, acked,
            )));
        }
        // P2 F6 (role fold): only the `Task` role folds into the TASKS section,
        // and that was already established inside the page transaction.
        let status = fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Queued);
        Ok(Some(TaskIntentPresence::new(
            task_hex, status, None, acked, jobs,
        )))
    }
}

/// Projects one surviving (non-cancelled) TASK entity into its board intent
/// row, or `None` when the entity is not a board-visible TASK. Returns an error
/// only for that single entity; the board scan degrades one bad entity into a
/// skip so the whole board survives (P2 F8).
pub(super) fn task_intent_presence(
    vault: &Vault,
    task_ref: EntityId,
    task_hex: &str,
    jobs: Vec<JobPresence>,
    acked: bool,
    now: u64,
) -> Result<Option<TaskIntentPresence>> {
    let slot = {
        let rtxn = vault.store.env.read_txn()?;
        task_page_slot_in(vault, &rtxn, task_ref, task_hex, jobs, acked, now)?
    };
    match slot {
        Some(slot) => slot.resolve(vault),
        None => Ok(None),
    }
}

/// The in-transaction half of [`task_intent_presence`]: everything the ordinary
/// typed and role-fallback paths need, read through the caller's transaction so
/// page hydration never opens a second one per id.
fn task_page_slot_in(
    vault: &Vault,
    rtxn: &heed::RoTxn<'_>,
    task_ref: EntityId,
    task_hex: &str,
    jobs: Vec<JobPresence>,
    acked: bool,
    now: u64,
) -> Result<Option<TaskPageSlot>> {
    if let Some(task) = task_verb_body_in(vault, rtxn, task_ref)? {
        let terminal = task.terminal().cloned();
        // ONE-1888: a deferring ladder terminal settles the LADDER on a row the
        // TASK axis deliberately keeps live. The escalation is the finest
        // outcome this row has, so the projection reads it off the interrupted
        // register rather than rendering the row as a bare pause.
        let settled_ladder = match &task.state {
            Some(TaskExecutionState::Interrupted { ladder }) => *ladder,
            _ => None,
        };
        let (status, terminal_disposition) = match (&terminal, task.ttl) {
            (Some(record), _) => (
                board_status_for_disposition(record.disposition),
                Some(record.disposition),
            ),
            // Derived, not stored: the deadline alone makes the row expired,
            // whether or not the reconciliation sweep has run yet. A settled
            // ladder is an ANSWER, so there is nothing for the deadline to
            // derive — the same reading the expiry sweep takes of that row.
            (None, Some(ttl)) if ttl.deadline_at < now && settled_ladder.is_none() => (
                TaskBoardStatus::Failed,
                Some(TaskTerminalDisposition::Expired),
            ),
            _ => (
                fold_up_status(&jobs).unwrap_or(TaskBoardStatus::Queued),
                None,
            ),
        };
        let kind = task.task_kind();
        let mut presence =
            TaskIntentPresence::new(task_hex.to_owned(), status, task.label, acked, jobs);
        presence.kind = Some(kind);
        // Display only. The row resolves a handle, storage keeps the actor ref;
        // an unregistered actor renders as its own id rather than as a guess.
        // A human assignee is qualified, because on the ONE shared TASKS
        // section the assignee column is what tells a reader that this open
        // loop is waiting on a person rather than on a worker.
        presence.assignee = task.assignee.and_then(|assignee| {
            let actor_ref = assignee.entity_ref()?;
            let handle = peer_handle_in(vault, rtxn, actor_ref)
                .ok()
                .flatten()
                .unwrap_or_else(|| actor_ref.to_hex());
            Some(match assignee {
                TaskAssignee::Human { .. } => format!("person:{handle}"),
                TaskAssignee::Dreamer
                | TaskAssignee::AgentDef { .. }
                | TaskAssignee::Peer { .. } => handle,
            })
        });
        presence.terminal_disposition = terminal_disposition;
        presence.result_ref = terminal
            .as_ref()
            .and_then(|record| record.result_ref)
            .or_else(|| settled_ladder.map(|ladder| ladder.result_ref))
            .map(|result_ref| result_ref.to_hex());
        // Terminal-only on purpose: the evidence-or-abstention summary is a
        // ONE-1699 answer, and an escalation is precisely the outcome that
        // produced none.
        presence.consult_result = terminal.as_ref().and_then(consult_result_presence);
        // ONE-1888: the ladder outcome is only ever read off the row that
        // actually carries one — either settled half — and an unstamped
        // ONE-1699 terminal keeps rendering exactly as it did.
        presence.ladder_disposition = terminal
            .as_ref()
            .and_then(|record| record.ladder)
            .or_else(|| settled_ladder.map(|ladder| ladder.disposition));
        presence.counter_task_ref = terminal
            .as_ref()
            .and_then(|record| record.counter_task_ref)
            .or_else(|| settled_ladder.and_then(|ladder| ladder.counter_task_ref))
            .map(|counter_ref| counter_ref.to_hex());
        presence.interrupted = matches!(task.state, Some(TaskExecutionState::Interrupted { .. }));
        return Ok(Some(TaskPageSlot::Projected(presence)));
    }
    // P2 F6 (role fold): only the `Task` role folds into the TASKS section.
    // Goal / Milestone / Habit / HabitCheckin roles are not tasks and must not
    // render as TASKS rows (nor enter the cancel fallback below). Both
    // remaining `Task`-role shapes — connector-send and role-only — are
    // finished once this transaction closes.
    if matches!(
        task_entity_role_in(vault, rtxn, task_ref)?,
        Some(TaskRole::Task)
    ) {
        return Ok(Some(TaskPageSlot::Untyped {
            task_ref,
            task_hex: task_hex.to_owned(),
            jobs,
            acked,
        }));
    }
    Ok(None)
}

/// Projects the terminal register's small typed summary. Refs only — a result
/// BODY never reaches a one-line board row.
fn consult_result_presence(record: &TaskTerminalRecord) -> Option<ConsultResultPresence> {
    let result_ref = record.result_ref?.to_hex();
    match record.summary.as_ref()? {
        ConsultResultSummary::Answer { evidence_refs } => Some(ConsultResultPresence::Answer {
            result_ref,
            evidence_ref_count: evidence_refs.len(),
        }),
        ConsultResultSummary::Abstained { reason_ref } => Some(ConsultResultPresence::Abstained {
            result_ref,
            reason_ref: reason_ref.short_ref(),
        }),
    }
}

fn collect_run_tree_nodes<'a>(nodes: &'a [RunTreeNode], out: &mut Vec<&'a RunTreeNode>) {
    for node in nodes {
        out.push(node);
        collect_run_tree_nodes(&node.children, out);
    }
}

pub(super) fn cancel_target_state(
    vault: &Vault,
    actor: EntityId,
    target: TaskCancelTarget,
) -> MemoryResult<CancelTargetState> {
    match target {
        TaskCancelTarget::Task(task_ref) => {
            let task_hex = task_ref.to_hex();
            let owned = if task_verb_body(vault, task_ref)?.is_some() {
                // The typed body is mutable storage and its `owner_ref` is not
                // authority. Only the Owner authority fact minted atomically by
                // the verified `tasks.create` path proves direct-cancel
                // ownership; typed bodies from any other write door fail
                // closed, and a task with no Owner fact proves nothing at all.
                //
                // The proof REPLICATES, so this is the same answer on the
                // machine that created the task and on every peer that
                // materialized it: the owner cancels their own task directly
                // instead of falling to the foreign, proposal-only ladder.
                task_create_owner(vault, task_ref)? == Some(actor)
            } else if let Some(task) = vault.connector_send_task(&task_ref)? {
                task.actor_ref == actor
            } else if matches!(task_entity_role(vault, task_ref)?, Some(TaskRole::Task)) {
                // P1-c (role-only ownership): a role-only TASK carries no stored
                // owner/author provenance (ONE-1695 role bodies are `{role}`
                // only, and no header / side-index / ledger records the author
                // of a raw TASK put). Ownership therefore cannot be established,
                // so fail CLOSED to the foreign ladder (propose-only) rather
                // than vacuously trusting the caller — no principal may directly
                // cancel another's role-only task. Visibility (fix-r1 F6) is
                // unaffected: role-only Tasks still render in `tasks.check` and
                // remain cancellable via a proposal. (F6 also narrows this
                // fallback to `Task`; Goal/Milestone/Habit/HabitCheckin ids are
                // not TASKS and fall through to `EntityNotFound`.)
                false
            } else {
                return Err(MemoryError::from(Error::EntityNotFound));
            };
            let attempts = AttemptQueue::new(vault)
                .list()?
                .into_iter()
                .filter(|attempt| attempt.task_ref.as_deref() == Some(task_hex.as_str()))
                .map(|attempt| (attempt.id, attempt.state))
                .collect();
            Ok(CancelTargetState {
                owned,
                task_ref: Some(task_ref),
                attempts,
                proposal_subject: task_ref,
                target_ref: task_hex,
            })
        }
        TaskCancelTarget::Spawn(attempt_ref) => {
            let queue = AttemptQueue::new(vault);
            let child = queue
                .get(attempt_ref)?
                .ok_or_else(|| MemoryError::from(Error::EntityNotFound))?;
            let child_payload = if child.kind == DREAMER_RUNNER_ATTEMPT_KIND {
                decode_dreamer_attempt_payload(&child.payload).ok()
            } else {
                None
            };
            let owned = child_payload
                .filter(|child| child.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE)
                .and_then(|child| child.parent_attempt)
                .and_then(|parent_ref| queue.get(parent_ref).ok().flatten())
                .and_then(|parent| decode_dreamer_attempt_payload(&parent.payload).ok())
                .filter(|parent| parent.attempt_type == AGENT_DISPATCH_ATTEMPT_TYPE)
                .and_then(|parent| decode_agent_dispatch_input(&parent.input).ok())
                .is_some_and(|parent| agent_dispatch_actor(&parent).entity_ref() == actor);
            Ok(CancelTargetState {
                owned,
                task_ref: None,
                attempts: vec![(attempt_ref, child.state)],
                proposal_subject: actor,
                target_ref: attempt_hex(attempt_ref),
            })
        }
    }
}

pub(super) fn attempt_hex(attempt_id: AttemptId) -> String {
    let mut out = String::with_capacity(32);
    for byte in attempt_id.as_bytes() {
        use std::fmt::Write as _;
        write!(&mut out, "{byte:02x}").expect("fmt::Write for String is infallible");
    }
    out
}

/// Attempt ids replaced by a later try.
///
/// A retry mints a NEW row and leaves its source terminally `Failed`, so the
/// rows behind one TASK are a forest of retry CHAINS, not a set of peers. Only
/// chain HEADS — rows no later try replaces — are live realizations; deciding
/// over every row decides over superseded history instead. Any-row status
/// precedence would fold a held retry up as `Failed` rather than `Scheduled`
/// and would keep folding a chain that later SUCCEEDED up as `Failed` forever,
/// and a cancel would rule against a dead source while its live successor
/// still runs and sends.
pub(super) fn superseded_attempt_ids(records: &[AttemptRecord]) -> HashSet<AttemptId> {
    records
        .iter()
        .filter_map(|record| record.retry_of)
        .collect()
}

/// Pre-lease states a task cancel can still stop in its own transaction.
///
/// A landing row is deliberately absent alongside a leased one: it holds a live
/// lease and is finishing bounded work, so the honest move is the soft rung, not
/// a synchronous kill it would have to refuse anyway.
pub(super) fn is_cancelable_attempt_state(state: AttemptState) -> bool {
    matches!(
        state,
        AttemptState::Queued | AttemptState::Paused | AttemptState::Scheduled
    )
}

/// States in which a worker holds the lease, so cancellation is a REQUEST.
pub(super) fn is_running_attempt_state(state: AttemptState) -> bool {
    state.is_running()
}

pub(super) fn terminal_attempt_status(
    attempts: &[(AttemptId, AttemptState)],
) -> Option<RunTreeStatus> {
    if attempts
        .iter()
        .any(|(_, state)| *state == AttemptState::Failed)
    {
        Some(RunTreeStatus::Failed)
    } else if attempts
        .iter()
        .any(|(_, state)| *state == AttemptState::Completed)
    {
        Some(RunTreeStatus::Completed)
    } else if attempts
        .iter()
        .any(|(_, state)| *state == AttemptState::Cancelled)
    {
        Some(RunTreeStatus::Cancelled)
    } else {
        None
    }
}
