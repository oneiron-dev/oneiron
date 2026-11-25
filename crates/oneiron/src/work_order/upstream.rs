//! An order that runs only after another (pass 34, 1.1; row Q5): the field `after` is looked
//! at before any machine is fitted, and only the other order's end releases it. That order
//! reaching `Done` releases it; that order giving up or being cancelled gives it up, naming
//! the order it waited on.
use crate::error::Result;
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{MEMORY_CODE_INVALID_STATE, MEMORY_CODE_NOT_FOUND, MemoryError};
use crate::{EntityId, Vault};

use super::blocker::Blocker;
use super::doors::{order_refusal, reaches};
use super::record::{AfterCondition, AfterOn, OrderState, WORK_ORDERS, WorkOrder};

/// Why an order with `after` cannot be fitted now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum UpstreamHold {
    /// The order it waits on is not at an end yet.
    Waiting(EntityId),
    /// The order it waits on ended without the end it waits for, or is gone.
    Ended(EntityId),
}

/// Whether `upstream`'s state releases an order that waits on it for `on`: `None` when it does,
/// else why not.
pub(super) fn upstream_hold(
    id: EntityId,
    upstream: Option<&WorkOrder>,
    on: AfterOn,
) -> Option<UpstreamHold> {
    let Some(upstream) = upstream else {
        return Some(UpstreamHold::Ended(id));
    };
    match (&upstream.state, on) {
        (OrderState::Done, AfterOn::Success) => None,
        (OrderState::GivenUp { .. } | OrderState::Cancelled { .. }, _) => {
            Some(UpstreamHold::Ended(id))
        }
        (OrderState::Open { .. } | OrderState::Running { .. }, _) => {
            Some(UpstreamHold::Waiting(id))
        }
    }
}

impl Vault {
    /// What holds `order` back on the order its `after` names, read in `txn`; `None` when it
    /// names none, or that order released it.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn upstream_hold_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        order: &WorkOrder,
    ) -> Result<Option<UpstreamHold>> {
        let Some(after) = order.after else {
            return Ok(None);
        };
        let upstream = WORK_ORDERS.get(&self.store, txn, &after.order)?;
        Ok(upstream_hold(after.order, upstream.as_ref(), after.on))
    }
}

/// The door's check of an order request's `after`, by `caller`, in the create's own `txn`: the
/// order it names is one the caller reads by `vault.jobs.orders.get`'s rule (the owner any; an
/// agent its own), and it has not ended without the end the request waits for.
///
/// # Errors
///
/// Storage errors. A refusal is the inner `Err`: `not_found` for an order the caller does not
/// read, which says nothing about another requester's orders; `invalid_state` with the reason
/// `after` for an order that already ended without that end.
pub(super) fn admit_after_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    after: &AfterCondition,
    caller: VerbGrantCaller,
) -> Result<std::result::Result<(), MemoryError>> {
    let upstream = WORK_ORDERS
        .get(&vault.store, txn, &after.order)?
        .filter(|upstream| reaches(caller, upstream));
    let Some(upstream) = upstream else {
        return Ok(Err(MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "after names no order you can read".to_owned(),
            &["Name an order of yours; vault.jobs.orders.list shows them."],
        )));
    };
    if let Some(UpstreamHold::Ended(order)) = upstream_hold(after.order, Some(&upstream), after.on)
    {
        return Ok(Err(upstream_ended_refusal(&order)));
    }
    Ok(Ok(()))
}

/// The refusal of an order whose `after` names `upstream`, an order that ended without the end
/// it waits for: `invalid_state` with the reason `after`. The order door answers it at
/// admission, and again when the door's own pass is what finds that end.
#[must_use]
pub fn upstream_ended_refusal(upstream: &EntityId) -> MemoryError {
    order_refusal(
        MEMORY_CODE_INVALID_STATE,
        "the order this one would wait on ended without the end it waits for; nothing is queued",
        &[Blocker::After {
            order: upstream.to_hex(),
        }],
    )
}
