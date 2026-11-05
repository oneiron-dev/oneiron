//! The next turn's prepared tail (I1 = C, ARCH-0067 "exact early
//! computation"), host side. Once a reply's canonical successor is
//! published, the session asks the turn's producer what the next turn is
//! known to start with past that path ([`super::NextTurnSource`]: the
//! state-only board, rendered now for the turn's reader) and has the worker
//! prefill it, as background work, beside the published checkpoint
//! (`session.prepare`). Nothing of it is published or canonical. At the next
//! fork the worker compares the real turn's own tokens with the tail's and
//! reuses only their identical beginning; the rest of the turn, its fresh
//! recall among it, is computed as before. A tail the real turn does not
//! match is wasted work, never a stale fact, and a prepare still running
//! when the turn arrives stops: no turn waits for one.
//!
//! The fixed policy decides by default: prepare after every publish while
//! `[models.sessions] prepare_tail` is on and the worker serves the op. The
//! learned planner (`planner = "learned"`, off by default) sits beside it
//! and skips a conversation's preparation once its earlier tails gave too
//! little; it learns from the forks' own reports. It never decides what a
//! fact is: the worker's token check does.
//!
//! What preparation computed, what the turns reused of it and what was
//! thrown away are counted for the status ([`status`]); a prepare that
//! stopped before it answered computed an unknown amount, counted apart.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use oneiron::llm::{
    CanonicalCheckpointRef, PreparedUse, SessionBinding, SessionOp, SessionOpStamp, SessionPrepare,
    SessionPrepared, SessionTarget, WorkClass, WorkPriority,
};
use serde_json::Value as JsonValue;

use super::NextTurnSource;
use super::policy;
use super::registry::{self, Place, Serves, send};
use crate::config::models::sessions::{PlannerMode, SessionPreparePolicy};
use crate::models::status::PreparedTailStatus;

/// The policy this process takes from `[models.sessions]`.
static POLICY: RwLock<SessionPreparePolicy> = RwLock::new(SessionPreparePolicy {
    prepare_tail: crate::config::models::sessions::DEFAULT_PREPARE_TAIL,
    planner: PlannerMode::Off,
});

/// Takes up the configured `[models.sessions]` policy.
pub(in crate::models::worker_host) fn set_policy(policy: SessionPreparePolicy) {
    *POLICY.write().unwrap_or_else(PoisonError::into_inner) = policy;
}

fn policy_now() -> SessionPreparePolicy {
    *POLICY.read().unwrap_or_else(PoisonError::into_inner)
}

/// What this process's preparations did since it started.
struct Counts {
    started: AtomicU64,
    ready: AtomicU64,
    stopped: AtomicU64,
    skipped_off: AtomicU64,
    skipped_planner: AtomicU64,
    skipped_unsupported: AtomicU64,
    skipped_no_tail: AtomicU64,
    attached: AtomicU64,
    missed: AtomicU64,
    computed_tokens: AtomicU64,
    reused_tokens: AtomicU64,
}

static COUNTS: Counts = Counts {
    started: AtomicU64::new(0),
    ready: AtomicU64::new(0),
    stopped: AtomicU64::new(0),
    skipped_off: AtomicU64::new(0),
    skipped_planner: AtomicU64::new(0),
    skipped_unsupported: AtomicU64::new(0),
    skipped_no_tail: AtomicU64::new(0),
    attached: AtomicU64::new(0),
    missed: AtomicU64::new(0),
    computed_tokens: AtomicU64::new(0),
    reused_tokens: AtomicU64::new(0),
};

fn add(counter: &AtomicU64, by: u64) {
    counter.fetch_add(by, Ordering::Relaxed);
}

/// The preparation counts as this process stands. Wasted tokens are those
/// computed and not reused: tails the turn diverged from, tails a park, an
/// eviction or a drop ended unused.
pub(in crate::models::worker_host) fn status() -> PreparedTailStatus {
    let read = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    let policy = policy_now();
    let computed = read(&COUNTS.computed_tokens);
    let reused = read(&COUNTS.reused_tokens);
    PreparedTailStatus {
        enabled: policy.prepare_tail,
        planner: policy.planner == PlannerMode::Learned,
        started: read(&COUNTS.started),
        ready: read(&COUNTS.ready),
        stopped: read(&COUNTS.stopped),
        skipped_off: read(&COUNTS.skipped_off),
        skipped_planner: read(&COUNTS.skipped_planner),
        skipped_unsupported: read(&COUNTS.skipped_unsupported),
        skipped_no_tail: read(&COUNTS.skipped_no_tail),
        attached: read(&COUNTS.attached),
        missed: read(&COUNTS.missed),
        computed_tokens: computed,
        reused_tokens: reused,
        wasted_tokens: computed.saturating_sub(reused),
    }
}

/// The learned planner's evidence for one conversation's binding: a running
/// mean of the share of each prepared tail its next turn reused, and how
/// many forks reported one.
#[derive(Clone, Copy)]
struct Evidence {
    reuse: f64,
    forks: u32,
}

/// The weight of each new fork's report in [`Evidence::reuse`].
const PLANNER_WEIGHT: f64 = 0.3;
/// The forks a conversation's tails are prepared for before the planner
/// judges them.
const PLANNER_MIN_FORKS: u32 = 3;
/// The reused share under which the planner stops preparing a
/// conversation's tails.
const PLANNER_MIN_REUSE: f64 = 0.25;
/// The conversations the planner keeps evidence for; past it, the binding
/// with the fewest forks goes.
const PLANNER_BINDINGS: usize = 4_096;

static EVIDENCE: Mutex<BTreeMap<SessionBinding, Evidence>> = Mutex::new(BTreeMap::new());

/// Whether the learned planner prepares `binding`'s next tail: until its
/// tails have been judged, and then only while turns reuse enough of them.
fn planner_prepares(binding: &SessionBinding) -> bool {
    let evidence = EVIDENCE.lock().unwrap_or_else(PoisonError::into_inner);
    evidence
        .get(binding)
        .is_none_or(|seen| seen.forks < PLANNER_MIN_FORKS || seen.reuse >= PLANNER_MIN_REUSE)
}

/// Takes one fork's report into `binding`'s evidence: the share of its tail
/// the turn reused, nothing for a prepare the turn stopped.
fn learn(binding: &SessionBinding, used: &PreparedUse) {
    #[allow(clippy::cast_precision_loss)]
    let share = if used.prepared_tokens == 0 {
        0.0
    } else {
        used.reused_tokens as f64 / used.prepared_tokens as f64
    };
    let mut evidence = EVIDENCE.lock().unwrap_or_else(PoisonError::into_inner);
    if !evidence.contains_key(binding)
        && evidence.len() >= PLANNER_BINDINGS
        && let Some(least) = evidence
            .iter()
            .min_by_key(|(_, seen)| seen.forks)
            .map(|(binding, _)| *binding)
    {
        evidence.remove(&least);
    }
    let seen = evidence.entry(*binding).or_insert(Evidence {
        reuse: share,
        forks: 0,
    });
    seen.reuse = if seen.forks == 0 {
        share
    } else {
        seen.reuse + PLANNER_WEIGHT * (share - seen.reuse)
    };
    seen.forks = seen.forks.saturating_add(1);
}

/// What a fork reported of the session's prepared tail: counted, and taken
/// into the planner's evidence for its binding.
pub(super) fn forked(binding: &SessionBinding, used: Option<&PreparedUse>) {
    let Some(used) = used else {
        return;
    };
    if used.stopped {
        add(&COUNTS.stopped, 1);
    } else if used.attached {
        add(&COUNTS.attached, 1);
    } else {
        add(&COUNTS.missed, 1);
    }
    add(&COUNTS.reused_tokens, used.reused_tokens);
    learn(binding, used);
}

/// A successor just published on a session, and what its next turn is
/// known to start with.
pub(super) struct Published {
    pub(super) worker_id: String,
    pub(super) place: Place,
    pub(super) binding: SessionBinding,
    pub(super) target: SessionTarget,
    pub(super) generation: u64,
    pub(super) checkpoint: CanonicalCheckpointRef,
    /// The published path as the wire carries it: its messages and tools.
    pub(super) conversation: JsonValue,
    pub(super) source: Arc<dyn NextTurnSource>,
}

/// Prepares `published`'s next tail on a task of its own, when the policy
/// says so. Returns at once.
pub(super) fn after_publish(published: Published) {
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        runtime.spawn(prepare(published));
    }
}

async fn prepare(published: Published) {
    let Published {
        worker_id,
        place,
        binding,
        target,
        generation,
        checkpoint,
        mut conversation,
        source,
    } = published;
    let policy = policy_now();
    if !policy.prepare_tail {
        add(&COUNTS.skipped_off, 1);
        return;
    }
    if policy.planner == PlannerMode::Learned && !planner_prepares(&binding) {
        add(&COUNTS.skipped_planner, 1);
        return;
    }
    if !serves_prepare(&worker_id, &place) {
        add(&COUNTS.skipped_unsupported, 1);
        return;
    }
    let tail = match source.next_tail().await {
        Some(tail) if !tail.is_empty() => tail,
        _ => {
            add(&COUNTS.skipped_no_tail, 1);
            return;
        }
    };
    let Some(messages) = conversation
        .get_mut("messages")
        .and_then(JsonValue::as_array_mut)
    else {
        return;
    };
    messages.extend(tail);
    // Only the session that published this successor, still at it.
    if !still_published(
        &worker_id,
        &place,
        &binding,
        &target,
        generation,
        &checkpoint,
    ) {
        return;
    }
    let body = SessionPrepare {
        target,
        stamp: SessionOpStamp {
            op_id: policy::next_op_id(),
            generation,
        },
        base: checkpoint,
        work_class: WorkClass::Background,
        priority: WorkPriority::Normal,
    };
    add(&COUNTS.started, 1);
    // A refusal is no fault of the session: the turn arrived, another
    // publish moved it, or it stopped serving. It goes on as it was.
    let prepared: Result<SessionPrepared, _> =
        send(&place, SessionOp::Prepare, &body, Some(&conversation)).await;
    match prepared {
        Ok(prepared) => {
            add(&COUNTS.ready, 1);
            add(&COUNTS.computed_tokens, prepared.computed_tokens);
            tracing::debug!(
                prepared_tokens = prepared.prepared_tokens,
                computed_tokens = prepared.computed_tokens,
                "a model session prepared its next turn's tail"
            );
        }
        Err(reason) => {
            add(&COUNTS.stopped, 1);
            tracing::debug!(?reason, "a model session's tail preparation stopped");
        }
    }
}

/// Whether the incarnation at `place` serves `session.prepare`.
fn serves_prepare(worker_id: &str, place: &Place) -> bool {
    registry::current(&mut registry::lock(), worker_id, place)
        .is_some_and(|worker| matches!(worker.serves, Serves::Yes(ops) if ops.prepare))
}

/// Whether `binding`'s session on `worker_id`'s incarnation at `place` is
/// still `target` at `generation`, publishing `checkpoint`.
fn still_published(
    worker_id: &str,
    place: &Place,
    binding: &SessionBinding,
    target: &SessionTarget,
    generation: u64,
    checkpoint: &CanonicalCheckpointRef,
) -> bool {
    registry::current(&mut registry::lock(), worker_id, place)
        .and_then(|worker| worker.sessions.get(binding))
        .is_some_and(|session| {
            session.handle == target.handle
                && session.generation == generation
                && session
                    .published
                    .as_ref()
                    .is_some_and(|published| published.same_point(checkpoint))
        })
}
