//! `vault.jobs.orders.wait` (pass 34, 14.2; row Q1): wait on one order until its first
//! started attempt or until its terminal state.
//!
//! In code mode the call parks the run on the order's wait ([`order_wait_id`]), and no model
//! turn runs while the machine works. The order's own writer settles that wait in the same
//! commit as the change that reaches the milestone ([`Vault::settle_order_waits_in_txn`]),
//! through the built code-run wait delivery: every run parked on it is delivered the settled
//! answer, and a run that parks after the settle finds it at once. A caller that cannot park
//! (MCP, HTTP) is answered at once ([`work_order_wait_as`]), with `reached` saying whether the
//! order has reached the milestone.
//!
//! An attempt is started on the machine's word, not when it is made: a made attempt may still
//! end `NeverStarted` (`OrderAttempt::started_at_ms`). An order at an end has reached both
//! milestones, so a started wait on an order that ended with no start answers its end.

use base64::Engine as _;
use oneiron_contracts::fingerprint::{Fingerprint, purposes};

use crate::consent::AuthenticatedOwner;
use crate::memory::{MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult};
use crate::{EntityId, Vault};

use super::ORDERS_WAIT_VERB;
use super::doors::{order_seen_by, reaches, seen_by_requester};
use super::record::{OrderAttempt, WORK_ORDERS, WorkOrder};
use super::wire::{
    AttemptReceipt, WaitUntil, WorkOrderView, WorkOrderWaitAnswer, WorkOrderWaitRequest,
};

/// Both milestones, in the order an order reaches them.
const MILESTONES: [WaitUntil; 2] = [WaitUntil::Started, WaitUntil::Terminal];

impl WaitUntil {
    /// The milestone's part of its wait id.
    const fn part(self) -> u8 {
        match self {
            Self::Started => 1,
            Self::Terminal => 2,
        }
    }

    /// The milestone's wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::Terminal => "terminal",
        }
    }
}

/// The code-run wait id of a wait on `order` until `until`: the id16 of the fingerprint
/// `purposes::work_order::WAIT_ID` over the order id and the milestone. Every run that waits on
/// the same order and milestone parks on the same wait, which the order's writer settles once.
///
/// # Errors
///
/// [`crate::Error::InvariantViolation`] in the one-in-2^128 case the digest is a reserved id.
pub fn order_wait_id(order: &EntityId, until: WaitUntil) -> crate::Result<EntityId> {
    let digest = Fingerprint::of_parts(
        purposes::work_order::WAIT_ID,
        &[&order.as_bytes()[..], &[until.part()][..]],
    );
    EntityId::from_bytes(digest.prefix::<16>())
        .map_err(|_| crate::Error::InvariantViolation("a work order wait id is reserved"))
}

impl WorkOrder {
    /// Whether the order has reached `until`: an order at an end has reached both; a started
    /// wait is also met by an attempt the machine started.
    #[must_use]
    pub fn reached(&self, until: WaitUntil) -> bool {
        self.state.is_terminal()
            || (until == WaitUntil::Started
                && self
                    .attempts
                    .iter()
                    .any(|attempt| attempt.started_at_ms.is_some()))
    }
}

impl Vault {
    /// The answer view of `order` in `txn`, with its last attempt's newest signed receipt.
    pub(super) fn order_view_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        order: WorkOrder,
        replayed: bool,
    ) -> crate::Result<WorkOrderView> {
        let receipt = match order.last_attempt() {
            Some(last) => self.attempt_receipt_in_txn(txn, last)?,
            None => None,
        };
        Ok(WorkOrderView {
            order,
            replayed,
            receipt,
        })
    }

    /// The newest receipt a node signed for `attempt`'s job, once one arrived.
    fn attempt_receipt_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: &OrderAttempt,
    ) -> crate::Result<Option<AttemptReceipt>> {
        let Some(job) = self.gpu_job_in_txn(txn, &attempt.job)? else {
            return Ok(None);
        };
        let Some(key) = job.chunk().map(|chunk| chunk.idempotency_key.clone()) else {
            return Ok(None);
        };
        Ok(self
            .job_observation_in_txn(txn, &key)?
            .map(|row| AttemptReceipt {
                attempt: attempt.n,
                key: row.key,
                machine: row.machine,
                signed: base64::engine::general_purpose::STANDARD.encode(&row.receipt),
                observed_at_ms: row.observed_at_ms,
            }))
    }

    /// Settles, in the order's own writer, each wait that `after` reaches and `before` (the row
    /// as stored, `None` for a new order) had not: every run parked on it is delivered the
    /// order's view as its requester reads it, frozen at this write.
    pub(super) fn settle_order_waits_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        before: Option<&WorkOrder>,
        after: &WorkOrder,
        now_ms: u64,
    ) -> crate::Result<()> {
        for until in MILESTONES {
            if !after.reached(until) || before.is_some_and(|stored| stored.reached(until)) {
                continue;
            }
            let view = self.order_view_in_txn(txn, seen_by_requester(after.clone()), false)?;
            let reply = serde_json::to_value(WorkOrderWaitAnswer {
                view,
                reached: true,
            })
            .map_err(|_| crate::Error::InvariantViolation("work order wait answer encode"))?;
            crate::code_run::deliver_wait_in_txn(
                self,
                txn,
                order_wait_id(&after.id, until)?,
                &reply,
                now_ms,
            )?;
        }
        Ok(())
    }

    /// Leaves the settled replies of `order`'s waits their erased form: the requester's erase
    /// scrubbed the order, and each reply copied it.
    pub(super) fn erase_order_wait_replies_in_txn(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        order: &EntityId,
    ) -> crate::Result<()> {
        for until in MILESTONES {
            crate::code_run::erase_settled_wait_reply_in_txn(
                self,
                wtxn,
                order_wait_id(order, until)?,
            )?;
        }
        Ok(())
    }
}

/// `vault.jobs.orders.wait` answered at once: the order as `memory`'s caller reads it and
/// whether it has reached `input.until`. The code-mode arm parks on [`order_wait_id`] when it
/// has not.
///
/// # Errors
///
/// `forbidden` for a caller the verb does not admit; `not_found` for an order the caller may
/// not read or that does not exist (the two answer alike, as `vault.jobs.orders.get`).
pub fn work_order_wait_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &WorkOrderWaitRequest,
) -> MemoryResult<WorkOrderWaitAnswer> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let caller = memory.verb_grant_caller_admits_in_txn(&txn, owner, ORDERS_WAIT_VERB)?;
    match WORK_ORDERS.get(&vault.store, &txn, &input.order)? {
        Some(order) if reaches(caller, &order) => {
            let reached = order.reached(input.until);
            let view = vault.order_view_in_txn(&txn, order_seen_by(caller, order), false)?;
            Ok(WorkOrderWaitAnswer { view, reached })
        }
        _ => Err(MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "no such work order",
            &["List the orders you may read with vault.jobs.orders.list."],
        )),
    }
}
