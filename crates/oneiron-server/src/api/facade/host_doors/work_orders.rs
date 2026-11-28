//! The work order doors (pass 34, 1.1 and 14): `vault.jobs.order`, `vault.jobs.orders.get`,
//! `.list` and `.cancel`, the read `vault.machines.place`, and `vault.jobs.logs.tail` (7.2: an
//! attempt's log, read on its machine; it may wait up to 60 s for bytes). Each proves
//! `verb_grant_caller`: the owner under his own proof, or an agent whose own live owner Grant
//! lists the verb, as the engine's read or write judges it again (`oneiron::work_order`).
//! Orders and dispatch rows live in side tables, which hold no entity row: the doors list none.
//!
//! An order is made on the issuer only (one issuer, pass 33, 8.7). The order door runs one pass
//! of the loop at once, under the loop's lock, so work that can run now starts now, work that
//! can never fit is refused with its reasons, and `wait: no` answers a refusal at once as the
//! built start does.

use std::sync::Arc;
use std::time::Duration;

use oneiron::memory::{
    MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_INVALID_STATE, MemoryError, MemoryResult,
};
use oneiron::work_order::{
    Blocker, Clearing, GiveUpWhy, LOGS_TAIL_VERB, LOGS_TAIL_WAIT_MAX_MS, LogsTail, LogsTailRequest,
    LogsTailStream, MACHINES_PLACE_VERB, MachinesPlaceRequest, MachinesPlaceView, ORDER_VERB,
    ORDERS_CANCEL_VERB, ORDERS_GET_VERB, ORDERS_LIST_VERB, ORDERS_WAIT_VERB, OrderCharge,
    OrderState, WorkOrderList, WorkOrderListRequest, WorkOrderRef, WorkOrderRequest, WorkOrderView,
    WorkOrderWaitAnswer, WorkOrderWaitRequest, allowed_machines, logs_tail_target_as,
    machines_place_as, order_refusal, order_work_as, ordered_view_as, upstream_ended_refusal,
    work_order_cancel_as, work_order_get_as, work_order_list_as, work_order_wait_as,
};

use super::support::Listed;
use super::verb_grant::verb_grant_door;
use crate::auth::CoreAuth;
use crate::gpu_execution_node::issuer::{NodeCallError, job_refusal_code, status_answer_kind};
use crate::gpu_execution_node::wire::{
    JobRefusal, JobStatusAnswer, LogStream, LogTailRequest, TAIL_MAX_BYTES,
};
use crate::gpu_host::now_ms;
use crate::server::SyncServer;
use crate::work_order_host::{
    dispatches_offer, locked_order_pass, machine_facts_now, tail_on_machine,
};

/// How often a waiting `vault.jobs.logs.tail` asks the machine again.
const LOGS_TAIL_ASK_EVERY: Duration = Duration::from_secs(1);

/// The refusal an order that ended at once answers: a spent budget when money is what stands
/// in its way, else an invalid state, with every blocker as a reason code (14.4). An order
/// whose `after` ended without its end answers as the door's admission does, whichever of the
/// two found that end first.
pub(super) fn refusal_of_end(why: &GiveUpWhy) -> Option<oneiron::memory::MemoryError> {
    let blocked = match why {
        GiveUpWhy::NeverFits { blocked } | GiveUpWhy::WaitEnded { blocked } => blocked,
        GiveUpWhy::Upstream { order } => return Some(upstream_ended_refusal(order)),
        GiveUpWhy::Ended { .. } | GiveUpWhy::WrittenOff => return None,
    };
    let blockers: Vec<Blocker> = blocked.iter().map(|on| on.blocker.clone()).collect();
    let money = blockers
        .iter()
        .any(|blocker| blocker.clearing() == Clearing::Money);
    let (code, message) = match (why, money) {
        (GiveUpWhy::NeverFits { .. }, _) => (
            MEMORY_CODE_INVALID_STATE,
            "the work can never fit any machine it may run on; nothing is queued",
        ),
        (_, true) => (MEMORY_CODE_BUDGET_SPENT, "the work cannot be paid for now"),
        (_, false) => (MEMORY_CODE_INVALID_STATE, "the work cannot run now"),
    };
    Some(order_refusal(code, message, &blockers))
}

/// `vault.jobs.order`: the owner, or an agent under its own Grant, orders one pinned workload.
/// One pass of the loop runs at once.
pub(crate) async fn vault_jobs_order(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkOrderRequest,
) -> Listed<WorkOrderView> {
    let shared = Arc::clone(server);
    verb_grant_door(server, auth, ORDER_VERB, move |server, memory, owner| {
        if let OrderCharge::Offer { name } = &input.charge
            && let Err(blocker) = dispatches_offer(server, name)
        {
            return Err(order_refusal(
                MEMORY_CODE_INVALID_STATE,
                "work orders are made on the vault's issuer",
                &[blocker],
            ));
        }
        let now = now_ms();
        let view = order_work_as(memory, owner, &input, now)?;
        if view.replayed {
            return Ok(view);
        }
        locked_order_pass(&shared, now)?;
        // Read again as the caller reads it: the pass's RANK decision may name other callers'
        // orders, which an agent does not see.
        let view = ordered_view_as(memory, owner, &view.order.id)?.unwrap_or(view);
        if let OrderState::GivenUp { why } = &view.order.state
            && let Some(refusal) = refusal_of_end(why)
        {
            return Err(refusal);
        }
        Ok(view)
    })
    .await
}

/// `vault.jobs.orders.get`: one order, as the caller may read it.
pub(crate) async fn vault_jobs_orders_get(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkOrderRef,
) -> Listed<WorkOrderView> {
    verb_grant_door(server, auth, ORDERS_GET_VERB, move |_, memory, owner| {
        work_order_get_as(memory, owner, &input)
    })
    .await
}

/// `vault.jobs.orders.wait`, answered at once: a caller outside code mode cannot be parked, so
/// `reached` says whether the order has reached `until`, and the caller asks again. A code-mode
/// run parks on the order's wait instead (`oneiron::code_run`, the run form of the same row).
pub(crate) async fn vault_jobs_orders_wait(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkOrderWaitRequest,
) -> Listed<WorkOrderWaitAnswer> {
    verb_grant_door(server, auth, ORDERS_WAIT_VERB, move |_, memory, owner| {
        work_order_wait_as(memory, owner, &input)
    })
    .await
}

/// `vault.jobs.orders.list`: the orders the caller may read, newest first.
pub(crate) async fn vault_jobs_orders_list(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkOrderListRequest,
) -> Listed<WorkOrderList> {
    verb_grant_door(server, auth, ORDERS_LIST_VERB, move |_, memory, owner| {
        work_order_list_as(memory, owner, &input)
    })
    .await
}

/// `vault.jobs.orders.cancel`: the owner cancels any order, an agent one it made. A running
/// order's attempt is stopped by the loop, woken at once.
pub(crate) async fn vault_jobs_orders_cancel(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: WorkOrderRef,
) -> Listed<WorkOrderView> {
    verb_grant_door(
        server,
        auth,
        ORDERS_CANCEL_VERB,
        move |server, memory, owner| {
            let view = work_order_cancel_as(memory, owner, &input, now_ms())?;
            server.gpu_jobs.orders().wake();
            Ok(view)
        },
    )
    .await
}

/// `vault.machines.place`: where an order of this workload would run now, each other allowed
/// machine's reasons, and the PLACE rule's pick. It starts nothing.
pub(crate) async fn vault_machines_place(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: MachinesPlaceRequest,
) -> Listed<MachinesPlaceView> {
    let shared = Arc::clone(server);
    verb_grant_door(
        server,
        auth,
        MACHINES_PLACE_VERB,
        move |server, memory, owner| place_now(&shared, server, memory, owner, &input),
    )
    .await
}

fn place_now(
    shared: &Arc<SyncServer>,
    server: &SyncServer,
    memory: &oneiron::memory::Memory<'_>,
    owner: Option<&oneiron::consent::AuthenticatedOwner>,
    input: &MachinesPlaceRequest,
) -> MemoryResult<MachinesPlaceView> {
    let now = now_ms();
    let machines = match server.vault.job_workload(&input.workload)? {
        Some(row) => machine_facts_now(shared, &allowed_machines(&input.limits, &row), now),
        None => Vec::new(),
    };
    machines_place_as(memory, owner, input, &machines, now)
}

/// `vault.jobs.logs.tail`: the owner, or an agent for an attempt it requested, reads bytes of
/// an attempt's stdout or stderr on the machine that runs it. With `wait_ms` the door asks the
/// machine again every second while it answers nothing new, until bytes arrive, the stream
/// ends or the wait passes (at most [`LOGS_TAIL_WAIT_MAX_MS`]); without it, one ask. Each ask
/// admits the caller again in the engine's read, so a revoke ends a wait at its next ask. Its
/// reply is never kept (`invocations::UNKEPT_REPLY_VERBS`): a same-id retry finds its admission
/// intent settled and is refused, and a new read asks the machine again.
pub(crate) async fn vault_jobs_logs_tail(
    server: &Arc<SyncServer>,
    auth: &CoreAuth,
    input: LogsTailRequest,
) -> Listed<LogsTail> {
    let wait = Duration::from_millis(input.wait_ms.unwrap_or(0).min(LOGS_TAIL_WAIT_MAX_MS));
    let started = tokio::time::Instant::now();
    loop {
        let shared = Arc::clone(server);
        let ask = input.clone();
        let (asked, rows) =
            verb_grant_door(server, auth, LOGS_TAIL_VERB, move |_, memory, owner| {
                let target = logs_tail_target_as(memory, owner, &ask)?;
                let request = LogTailRequest {
                    key: target.key,
                    stream: match ask.stream {
                        LogsTailStream::Stdout => LogStream::Stdout,
                        LogsTailStream::Stderr => LogStream::Stderr,
                    },
                    offset: ask.offset,
                    max: ask.max.unwrap_or(TAIL_MAX_BYTES).min(TAIL_MAX_BYTES),
                };
                tail_asked(tail_on_machine(&shared, target.machine, request))
            })
            .await;
        let remaining = wait.saturating_sub(started.elapsed());
        match asked {
            Ok(TailAsked::Read(tail)) if !waits_for_more(&tail) || remaining.is_zero() => {
                return (Ok(tail), rows);
            }
            Ok(TailAsked::Busy) if remaining.is_zero() => {
                return (
                    Err(tail_refusal(
                        "log_busy",
                        "the machine is turning the log over",
                        true,
                    )),
                    rows,
                );
            }
            Ok(TailAsked::Read(_) | TailAsked::Busy) => {
                tokio::time::sleep(remaining.min(LOGS_TAIL_ASK_EVERY)).await;
            }
            Err(error) => return (Err(error), rows),
        }
    }
}

/// What one ask of the machine answered.
enum TailAsked {
    /// The bytes from the offset; there may be none yet.
    Read(LogsTail),
    /// The machine is turning the log over: ask again.
    Busy,
}

/// Whether a read may wait for more: it holds no bytes, no end and no gap.
fn waits_for_more(tail: &LogsTail) -> bool {
    tail.bytes.is_empty() && !tail.ended && tail.truncated.is_none()
}

/// The machine's answer to one `Tail`, or the refusal the caller reads, with the node's own
/// code for a refusal the node wrote (EM-19).
fn tail_asked(answer: Result<JobStatusAnswer, NodeCallError>) -> MemoryResult<TailAsked> {
    let (code, message, transient) = match answer {
        Ok(JobStatusAnswer::Tail(tail)) => {
            return Ok(TailAsked::Read(LogsTail::from_machine(
                &tail.bytes,
                tail.next_offset,
                tail.ended,
                tail.truncated.map(|truncation| truncation.dropped),
            )));
        }
        Ok(JobStatusAnswer::Busy { .. }) => return Ok(TailAsked::Busy),
        Ok(JobStatusAnswer::Refused(JobRefusal::LogNotReadable { why })) => (
            "log_not_readable",
            format!("the machine does not read this log: {why}"),
            false,
        ),
        Ok(JobStatusAnswer::Refused(refusal)) => (
            job_refusal_code(&refusal),
            "the machine refused the read".to_owned(),
            false,
        ),
        Ok(JobStatusAnswer::Absent { .. }) => (
            "attempt_not_on_machine",
            "the machine's journal holds no such attempt".to_owned(),
            false,
        ),
        Ok(JobStatusAnswer::HistoryLost) => (
            "history_lost",
            "the machine lost the journal that held the attempt".to_owned(),
            false,
        ),
        Ok(other) => (
            "unexpected_answer",
            format!("the machine answered {}", status_answer_kind(&other)),
            false,
        ),
        Err(NodeCallError::Timeout) => (
            "machine_unreachable",
            "the machine did not answer in time".to_owned(),
            true,
        ),
        Err(NodeCallError::Unreachable { reason }) => (
            "machine_unreachable",
            format!("the machine cannot be reached: {reason}"),
            true,
        ),
    };
    Err(tail_refusal(code, message, transient))
}

/// A refusal of `vault.jobs.logs.tail` with its reason `code`. A `transient` one passes: the
/// caller asks again from the same offset.
fn tail_refusal(code: &str, message: impl Into<String>, transient: bool) -> MemoryError {
    let suggestions: &[&str] = if transient {
        &["Ask again from the same offset."]
    } else {
        &[]
    };
    let mut error = MemoryError::new(MEMORY_CODE_INVALID_STATE, message, suggestions);
    error.reason_codes = vec![code.to_owned()];
    error
}
