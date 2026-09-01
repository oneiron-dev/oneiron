//! Durable code-mode wave orchestration over TASK entities and the C9 run
//! tree (ONE-1905, CSTDY-05).
//!
//! A wave is composed in ORDINARY CODE, never in a workflow DSL: a
//! [`WavePlanner`] returns one typed task cut, [`WaveOrchestrator::validate`]
//! validates that cut in full BEFORE any TASK row is written, and a
//! [`WaveTaskPort`] lands the TASK rows plus one typed `blocked_by` edge per
//! dependency. Loops, joins, retries and fan-out stay orchestrator code over
//! [`WaveOrchestrator::ready_set`], task writes, and the existing attempt
//! queue / run tree: this module owns no scheduler, no interpreter, and no
//! storage.
//!
//! Three laws are structural here rather than conventional:
//!
//! * **PLAN is itself a task/attempt** — [`WavePlanRequest`] carries the
//!   planner's [`AttemptId`] and the planning work rides
//!   [`WAVE_PLAN_ATTEMPT_KIND`] on the existing queue. Nothing here enqueues,
//!   leases, or dispatches; `attempt_queue/`, `run_tree.rs` and
//!   `agent_dispatch.rs` are consumed READ-ONLY.
//! * **readiness is COMPUTED at read time** — [`WaveOrchestrator::ready`]
//!   re-reads the blockers and their terminal state on every call. There is no
//!   readiness counter, `blocked` status, claim row, projector table, or repair
//!   loop; flipping a blocker's terminal state flips readiness with no
//!   maintenance step in between (ARCH-0068 §RC5, mirrored by the
//!   [`crate::edge::EdgeKind::BlockedBy`] doc).
//! * **the edge is typed and gated** — every `blocked_by` write goes through
//!   [`blocked_by_edge_write`], which refuses any endpoint whose registry type
//!   byte is not [`ENTITY_TYPE_TASK`] (101). The edge is directed
//!   dependent → blocker, rides the structural 12-byte layout with no PPR
//!   weight prior, and is never traversed by PPR or the context-pack walk.
//!
//! The ABI belongs to `edge.rs` and `task_verb/` (ONE-1924): this module mints
//! nothing and persists nothing itself. Durability is the injected
//! [`WaveTaskPort`]'s job, which is also why the whole organ is testable with
//! fakes and no vault.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::attempt_queue::AttemptId;
use crate::edge::EdgeKind;
use crate::entity_id::EntityId;
use crate::linear_sync::{LinearSyncError, WaveResult};
use crate::registry::ENTITY_TYPE_TASK;

/// Wire version of the [`WavePlan`] a planner returns.
pub const WAVE_PLAN_SCHEMA_VERSION: u8 = 1;

/// Attempt kind the planning step rides on the existing attempt queue: the
/// PLAN is a task/attempt like any other, not a privileged engine phase.
pub const WAVE_PLAN_ATTEMPT_KIND: &str = "wave.plan";

/// The `blocked_by` edge discriminant, pinned to the ARCH-0034 `edgeKinds`
/// registry byte owned by [`crate::edge::EdgeKind::BlockedBy`].
pub const BLOCKED_BY_EDGE_U8: u8 = 23;

/// Upper bound on the tasks one validated plan may carry.
///
/// A cut this large is a planner defect, not a legitimate wave: the bound
/// fails the plan LOUD before any TASK row is written rather than letting a
/// runaway planner mint an unbounded task fan-out.
pub const MAX_WAVE_PLAN_TASKS: usize = 256;

const _: () = assert!(
    BLOCKED_BY_EDGE_U8 == EdgeKind::BlockedBy as u8,
    "wave_orchestration must stay pinned to the registry blocked_by discriminant"
);

const ERR_SCHEMA_VERSION: &str = "wave_orchestration: unsupported wave plan schema version";
const ERR_EMPTY_PLAN_REF: &str = "wave_orchestration: wave plan carries an empty plan_ref";
const ERR_EMPTY_PLAN: &str = "wave_orchestration: wave plan carries no tasks";
const ERR_PLAN_TOO_LARGE: &str = "wave_orchestration: wave plan exceeds the task bound";
const ERR_EMPTY_LOCAL_KEY: &str = "wave_orchestration: planned task carries an empty local_key";
const ERR_DUPLICATE_LOCAL_KEY: &str = "wave_orchestration: planned task local_key is duplicated";
const ERR_UNKNOWN_BLOCKER: &str = "wave_orchestration: planned task blocks on an unknown key";
const ERR_SELF_EDGE: &str = "wave_orchestration: planned task blocks on itself";
const ERR_DUPLICATE_BLOCKER: &str = "wave_orchestration: planned task repeats a blocker key";
const ERR_CYCLE: &str = "wave_orchestration: wave plan blocked_by graph contains a cycle";
const ERR_NOT_TASK_ENTITY: &str = "wave_orchestration: blocked_by endpoint is not a TASK entity";
const ERR_WRITE_UNKNOWN_KEY: &str = "wave_orchestration: task port returned an unplanned key";
const ERR_WRITE_DUPLICATE: &str = "wave_orchestration: task port returned a duplicate local_key";
const ERR_WRITE_MISSING: &str = "wave_orchestration: task port skipped a planned task";
const ERR_WRITE_BLOCKERS: &str = "wave_orchestration: task port blocker refs contradict the plan";

fn invariant(message: &'static str) -> LinearSyncError {
    LinearSyncError::Store(crate::error::Error::InvariantViolation(message))
}

/// What the orchestrator asks a planner to cut into tasks.
///
/// `planner_attempt_ref` is the attempt the planning work itself runs under —
/// the PLAN is a task/attempt, so its provenance is an ordinary queue row.
#[derive(Debug, Clone, PartialEq)]
pub struct WavePlanRequest {
    /// The EPIC-level TASK the cut hangs under.
    pub epic_task_ref: EntityId,
    /// Attempt the planning step runs under.
    pub planner_attempt_ref: AttemptId,
    /// Human-readable statement of what the wave must achieve.
    pub objective: String,
    /// Caller-supplied planning constraints, opaque to the engine.
    pub constraints: Value,
    /// Wall-clock stamp of the request, in the caller's unit.
    pub now: u64,
}

/// One task a planner proposes, addressed by a plan-local key.
///
/// `blocked_by` is expressed in LOCAL keys because the plan is validated
/// before any TASK row exists: entity ids only appear once the
/// [`WaveTaskPort`] has landed the rows.
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedTask {
    /// Plan-local identity, unique within one [`WavePlan`].
    pub local_key: String,
    /// Short label for the minted TASK row.
    pub label: String,
    /// Engine-opaque task specification handed to the executor.
    pub spec: Value,
    /// Optional assignee for the minted TASK row.
    pub assignee_ref: Option<EntityId>,
    /// Local keys this task is blocked by; the edge runs dependent → blocker.
    pub blocked_by: Vec<String>,
}

/// The typed task cut a [`WavePlanner`] returns, before validation.
#[derive(Debug, Clone, PartialEq)]
pub struct WavePlan {
    /// Must equal [`WAVE_PLAN_SCHEMA_VERSION`].
    pub schema_version: u8,
    /// Stable identity of this cut, reused across idempotent applies.
    pub plan_ref: String,
    /// The EPIC-level TASK the cut hangs under.
    pub epic_task_ref: EntityId,
    /// The proposed tasks, in planner order.
    pub tasks: Vec<PlannedTask>,
}

/// A plan that passed every structural check in
/// [`WaveOrchestrator::validate`].
///
/// Only this type can reach [`WaveTaskPort::apply_validated_plan`], which is
/// how "validate before any TASK write" is enforced by the type system rather
/// than by discipline.
///
/// Not `Eq`: [`PlannedTask::spec`] is a `serde_json::Value`, which is
/// `PartialEq` but never `Eq`.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedWavePlan {
    /// Stable identity of the cut.
    pub plan_ref: String,
    /// The EPIC-level TASK the cut hangs under.
    pub epic_task_ref: EntityId,
    /// Deterministic topological order: every blocker precedes its dependents,
    /// ties broken by local key so two runs of the same plan agree.
    pub topological_order: Vec<String>,
    /// The validated tasks, keyed by local key.
    pub tasks: BTreeMap<String, PlannedTask>,
}

/// Cuts an objective into a typed task plan.
///
/// Implementations are ordinary code (an LLM call, a template, a hand-written
/// cut); the engine never interprets a plan language.
pub trait WavePlanner {
    /// Returns the task cut for one request.
    ///
    /// # Errors
    ///
    /// Returns an error when the planner cannot produce a well-formed cut.
    fn cut_plan(&self, request: WavePlanRequest) -> WaveResult<WavePlan>;
}

/// One TASK row a [`WaveTaskPort`] landed for a planned task.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaveTaskWrite {
    /// The plan-local key this row was minted for.
    pub local_key: String,
    /// The minted (or re-used, on an idempotent re-apply) TASK entity.
    pub task_ref: EntityId,
    /// Label written onto the TASK row.
    pub label: String,
    /// Assignee written onto the TASK row, if any.
    pub assignee_ref: Option<EntityId>,
    /// Blocker TASK entities, in the same order as the planned `blocked_by`
    /// local keys.
    pub blocker_refs: Vec<EntityId>,
}

/// The durable side of a wave: TASK rows, `blocked_by` edges, and the two
/// reads readiness is computed from.
///
/// Implementations own persistence AND the type-101 gate: every `blocked_by`
/// edge must be built with [`blocked_by_edge_write`] so a non-TASK endpoint
/// can never acquire one.
pub trait WaveTaskPort {
    /// Lands every task in `plan` plus its `blocked_by` edges, idempotently
    /// per `(plan_ref, local_key)`.
    ///
    /// # Errors
    ///
    /// Returns an error when a row or edge cannot be written, including when
    /// an endpoint fails the [`ENTITY_TYPE_TASK`] gate.
    fn apply_validated_plan(
        &mut self,
        plan: &ValidatedWavePlan,
        now: u64,
    ) -> WaveResult<Vec<WaveTaskWrite>>;

    /// Whether `task_ref` reached a SUCCESSFUL terminal state
    /// (`crate::task_verb::TaskTerminalDisposition::Completed`); a failed,
    /// rejected, or expired blocker keeps its dependents unready.
    ///
    /// # Errors
    ///
    /// Returns an error when the task state cannot be read.
    fn task_terminal_success(&self, task_ref: EntityId) -> WaveResult<bool>;

    /// The current outgoing `blocked_by` targets of `task_ref`.
    ///
    /// # Errors
    ///
    /// Returns an error when the edges cannot be read.
    fn blockers(&self, task_ref: EntityId) -> WaveResult<Vec<EntityId>>;
}

/// What one apply of a validated plan landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WavePlanReceipt {
    /// Identity of the applied cut.
    pub plan_ref: String,
    /// Minted TASK entity per plan-local key.
    pub task_refs: BTreeMap<String, EntityId>,
    /// Distinct dependent → blocker edges the plan implies.
    pub blocked_by_edges: usize,
    /// Wall-clock stamp the apply was performed at.
    pub applied_at: u64,
}

/// One typed dependent → blocker `blocked_by` edge that already passed the
/// TASK-type gate.
///
/// Constructing this value is the ONLY way this module hands an edge to a
/// port, so "verify both endpoints are TASK entities before writing" is a
/// type-level obligation instead of a review note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlockedByEdgeWrite {
    /// The blocked (dependent) TASK — the edge SOURCE.
    pub dependent: EntityId,
    /// The blocking TASK — the edge TARGET.
    pub blocker: EntityId,
}

impl BlockedByEdgeWrite {
    /// The edge kind this write lands: always
    /// [`crate::edge::EdgeKind::BlockedBy`] (byte [`BLOCKED_BY_EDGE_U8`]),
    /// structural layout, no PPR weight prior.
    #[must_use]
    pub const fn kind(self) -> EdgeKind {
        EdgeKind::BlockedBy
    }
}

/// Builds one `blocked_by` edge write after checking both endpoints.
///
/// The caller passes the registry type byte it read for each endpoint; both
/// must be [`ENTITY_TYPE_TASK`] (101). A self-edge is refused here too, so a
/// port cannot reintroduce one that validation already rejected.
///
/// # Errors
///
/// Returns an invariant violation when either endpoint is not a TASK entity,
/// or when `dependent == blocker`.
pub fn blocked_by_edge_write(
    dependent: EntityId,
    dependent_type: u8,
    blocker: EntityId,
    blocker_type: u8,
) -> WaveResult<BlockedByEdgeWrite> {
    if dependent_type != ENTITY_TYPE_TASK || blocker_type != ENTITY_TYPE_TASK {
        return Err(invariant(ERR_NOT_TASK_ENTITY));
    }
    if dependent == blocker {
        return Err(invariant(ERR_SELF_EDGE));
    }
    Ok(BlockedByEdgeWrite { dependent, blocker })
}

/// Composes waves over a [`WaveTaskPort`]: validate, apply, then compute
/// readiness on every read.
#[derive(Debug)]
pub struct WaveOrchestrator<P> {
    tasks: P,
}

impl<P> WaveOrchestrator<P> {
    /// Wraps a task port.
    pub const fn new(tasks: P) -> Self {
        Self { tasks }
    }

    /// Borrows the wrapped port.
    pub const fn tasks(&self) -> &P {
        &self.tasks
    }

    /// Mutably borrows the wrapped port.
    pub fn tasks_mut(&mut self) -> &mut P {
        &mut self.tasks
    }

    /// Unwraps the port.
    pub fn into_tasks(self) -> P {
        self.tasks
    }
}

impl<P: WaveTaskPort> WaveOrchestrator<P> {
    /// Fully validates a planner's cut BEFORE any TASK row exists.
    ///
    /// Checks, in order: schema version, non-empty plan ref, non-empty and
    /// bounded task count, non-empty and unique local keys, known blockers, no
    /// self-edge, no repeated blocker, and no cycle. The returned plan carries
    /// a deterministic topological order (blockers first, ties broken by local
    /// key).
    ///
    /// # Errors
    ///
    /// Returns an invariant violation naming the first structural defect
    /// found; nothing is written on any path through this function.
    pub fn validate(plan: WavePlan) -> WaveResult<ValidatedWavePlan> {
        if plan.schema_version != WAVE_PLAN_SCHEMA_VERSION {
            return Err(invariant(ERR_SCHEMA_VERSION));
        }
        if plan.plan_ref.trim().is_empty() {
            return Err(invariant(ERR_EMPTY_PLAN_REF));
        }
        if plan.tasks.is_empty() {
            return Err(invariant(ERR_EMPTY_PLAN));
        }
        if plan.tasks.len() > MAX_WAVE_PLAN_TASKS {
            return Err(invariant(ERR_PLAN_TOO_LARGE));
        }

        let mut tasks: BTreeMap<String, PlannedTask> = BTreeMap::new();
        for task in plan.tasks {
            if task.local_key.trim().is_empty() {
                return Err(invariant(ERR_EMPTY_LOCAL_KEY));
            }
            if tasks.insert(task.local_key.clone(), task).is_some() {
                return Err(invariant(ERR_DUPLICATE_LOCAL_KEY));
            }
        }
        check_blocker_references(&tasks)?;

        let topological_order = topological_order(&tasks)?;
        Ok(ValidatedWavePlan {
            plan_ref: plan.plan_ref,
            epic_task_ref: plan.epic_task_ref,
            topological_order,
            tasks,
        })
    }

    /// Applies a validated plan through the port and reconciles what came
    /// back against the plan.
    ///
    /// The port owns the writes; this function owns the proof that the writes
    /// match the cut — every planned key landed exactly once, and every
    /// blocker ref is the ref minted for that blocker's local key. Re-applying
    /// the same validated plan through an idempotent port yields an identical
    /// receipt, so no duplicate TASK rows or edges appear.
    ///
    /// # Errors
    ///
    /// Returns the port's error, or an invariant violation when the returned
    /// writes do not match the plan.
    pub fn apply(&mut self, plan: ValidatedWavePlan, now: u64) -> WaveResult<WavePlanReceipt> {
        let writes = self.tasks.apply_validated_plan(&plan, now)?;
        let mut task_refs: BTreeMap<String, EntityId> = BTreeMap::new();
        for write in &writes {
            if !plan.tasks.contains_key(&write.local_key) {
                return Err(invariant(ERR_WRITE_UNKNOWN_KEY));
            }
            if task_refs
                .insert(write.local_key.clone(), write.task_ref)
                .is_some()
            {
                return Err(invariant(ERR_WRITE_DUPLICATE));
            }
        }
        if task_refs.len() != plan.tasks.len() {
            return Err(invariant(ERR_WRITE_MISSING));
        }

        let mut edges: BTreeSet<(EntityId, EntityId)> = BTreeSet::new();
        for write in &writes {
            let planned = plan
                .tasks
                .get(&write.local_key)
                .ok_or_else(|| invariant(ERR_WRITE_UNKNOWN_KEY))?;
            if planned.blocked_by.len() != write.blocker_refs.len() {
                return Err(invariant(ERR_WRITE_BLOCKERS));
            }
            for (blocker_key, blocker_ref) in planned.blocked_by.iter().zip(&write.blocker_refs) {
                let expected = task_refs
                    .get(blocker_key)
                    .ok_or_else(|| invariant(ERR_WRITE_BLOCKERS))?;
                if expected != blocker_ref {
                    return Err(invariant(ERR_WRITE_BLOCKERS));
                }
                edges.insert((write.task_ref, *blocker_ref));
            }
        }

        Ok(WavePlanReceipt {
            plan_ref: plan.plan_ref,
            task_refs,
            blocked_by_edges: edges.len(),
            applied_at: now,
        })
    }

    /// Whether `task_ref` is ready right now.
    ///
    /// COMPUTED on every call from the current `blocked_by` edges and the
    /// current terminal state of each blocker. Nothing is cached, stamped, or
    /// repaired: a blocker completing makes its dependents ready on the very
    /// next read.
    ///
    /// # Errors
    ///
    /// Returns the port's error when the edges or task states cannot be read.
    pub fn ready(&self, task_ref: EntityId) -> WaveResult<bool> {
        for blocker in self.tasks.blockers(task_ref)? {
            if !self.tasks.task_terminal_success(blocker)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// The ready subset of `task_refs`, in the caller's order.
    ///
    /// This is the whole scheduler surface: fan-out, joins, and retries are
    /// ordinary orchestrator code over this slice plus task writes.
    ///
    /// # Errors
    ///
    /// Returns the port's error when the edges or task states cannot be read.
    pub fn ready_set(&self, task_refs: &[EntityId]) -> WaveResult<Vec<EntityId>> {
        let mut ready = Vec::new();
        for task_ref in task_refs {
            if self.ready(*task_ref)? {
                ready.push(*task_ref);
            }
        }
        Ok(ready)
    }
}

/// Rejects unknown, self-referential, and repeated blocker references.
fn check_blocker_references(tasks: &BTreeMap<String, PlannedTask>) -> WaveResult<()> {
    for (local_key, task) in tasks {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        for blocker in &task.blocked_by {
            if blocker == local_key {
                return Err(invariant(ERR_SELF_EDGE));
            }
            if !tasks.contains_key(blocker) {
                return Err(invariant(ERR_UNKNOWN_BLOCKER));
            }
            if !seen.insert(blocker.as_str()) {
                return Err(invariant(ERR_DUPLICATE_BLOCKER));
            }
        }
    }
    Ok(())
}

/// Deterministic Kahn ordering: blockers before dependents, lexicographic
/// frontier so the same plan always yields the same order.
fn topological_order(tasks: &BTreeMap<String, PlannedTask>) -> WaveResult<Vec<String>> {
    let mut blocker_count: BTreeMap<&str, usize> = tasks
        .iter()
        .map(|(key, task)| (key.as_str(), task.blocked_by.len()))
        .collect();
    let mut dependents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (key, task) in tasks {
        for blocker in &task.blocked_by {
            dependents
                .entry(blocker.as_str())
                .or_default()
                .push(key.as_str());
        }
    }

    let mut frontier: BTreeSet<&str> = blocker_count
        .iter()
        .filter(|(_, count)| **count == 0)
        .map(|(key, _)| *key)
        .collect();
    let mut order: Vec<String> = Vec::with_capacity(tasks.len());
    while let Some(key) = frontier.pop_first() {
        blocker_count.remove(key);
        order.push(key.to_owned());
        let Some(children) = dependents.get(key) else {
            continue;
        };
        for &child in children {
            let Some(count) = blocker_count.get_mut(child) else {
                continue;
            };
            *count -= 1;
            if *count == 0 {
                frontier.insert(child);
            }
        }
    }

    if order.len() != tasks.len() {
        return Err(invariant(ERR_CYCLE));
    }
    Ok(order)
}

#[cfg(test)]
mod tests;
