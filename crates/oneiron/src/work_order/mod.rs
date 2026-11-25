//! Work orders (pass 34, `34-compute-general/DESIGN.md` sections 0 and 1; Engine rulings EM-18,
//! EM-19 and EM-22 = A): durable intent to run a pinned workload, above the built job. An open
//! order holds no device and no money. The loop ([`pass`]) fits each open order over the
//! machines' reported facts ([`fit`]), ranks the runnable ones ([`rank`]), places each
//! ([`place`]) and makes an attempt through the built quote and start, which write the job and
//! the order's attempt entry in one write. When an attempt ends, the AFTER rule ([`after`])
//! decides: done, another attempt under a new key, or give up. Why an order waits is one typed
//! list of [`Blocker`]s, the same words the start gate and the node use.
//!
//! An order may wait on another order's end ([`upstream`]), count against named running caps
//! ([`caps`]), and be a member of an array whose group row caps its running members
//! ([`group`]) (row Q5).
//!
//! Orders live on the issuer; the doors are `vault.jobs.order`, `vault.jobs.orders.get`,
//! `.list`, `.cancel` and `.wait` ([`wait`]: in code mode it parks the run until the order's
//! writer settles it), the read `vault.machines.place`, and `vault.jobs.logs.tail` (an
//! attempt's log, read on its machine: [`logs_tail`] says who may read it and where).

pub mod after;
pub mod blocker;
pub mod caps;
mod conditions;
pub mod decider;
mod doors;
pub mod fit;
pub mod group;
pub mod logs_tail;
pub mod pass;
pub mod place;
pub mod rank;
pub mod record;
pub(crate) mod setting_keys;
pub mod start_check;
pub(crate) mod tables;
mod upstream;
pub mod wait;
mod wire;

pub use after::{AFTER_RULE, AfterPick, RetryPolicy, RetryRule, after_rule};
pub use blocker::{BlockedOn, Blocker, Clearing};
pub use caps::{
    CAP_NAME_MAX, CAPS_PER_ORDER_MAX, GROUP_CAP_PREFIX, RunningCaps, group_cap_name, is_cap_name,
};
pub use doors::{
    CancelRefused, ORDER_INTENT_KEY_MAX, machines_place_as, order_refusal, order_work_as,
    ordered_view_as, work_order_cancel_as, work_order_get_as, work_order_list_as,
};
pub use fit::{
    DeviceFact, MachineFacts, MachineReach, Needs, Room, TemplateFact, WindowFact, fit,
    scope_allowed, scope_kind_name,
};
pub use group::{GroupRequest, WorkOrderGroup};
pub use logs_tail::{
    LOGS_TAIL_WAIT_MAX_MS, LogsTail, LogsTailRequest, LogsTailStream, LogsTailTarget,
    LogsTailTruncation, logs_tail_target_as,
};
pub use pass::{AttemptOutcome, AttemptToMake, OrderHost, PassReport, allowed_machines};
pub use place::{PLACE_RULE, place};
pub use rank::{RANK_RULE, rank};
pub use record::{
    AfterCondition, AfterOn, AttemptEnd, CancelAsk, CancelWhy, DecidedBy, EndKind, GiveUpWhy,
    GroupMember, OrderAttempt, OrderCharge, OrderClass, OrderLimits, OrderState, OrderWishes,
    OrderedBy, ResultBinding, SlotDecision, SlotName, WaitRule, WorkOrder, attempt_job_id,
};
pub use start_check::{AttemptRefused, OrderAttemptRef, OrderStarter};
pub use upstream::upstream_ended_refusal;
pub use wait::{order_wait_id, work_order_wait_as};
pub use wire::{
    AttemptReceipt, MachinesPlaceRequest, MachinesPlaceView, WaitUntil, WorkOrderList,
    WorkOrderListRequest, WorkOrderRef, WorkOrderRequest, WorkOrderView, WorkOrderWaitAnswer,
    WorkOrderWaitRequest,
};

use crate::{EntityId, Vault};

/// `vault.jobs.order`.
pub const ORDER_VERB: &str = "vault.jobs.order";
/// `vault.jobs.orders.get`.
pub const ORDERS_GET_VERB: &str = "vault.jobs.orders.get";
/// `vault.jobs.orders.list`.
pub const ORDERS_LIST_VERB: &str = "vault.jobs.orders.list";
/// `vault.jobs.orders.cancel`.
pub const ORDERS_CANCEL_VERB: &str = "vault.jobs.orders.cancel";
/// `vault.jobs.orders.wait`.
pub const ORDERS_WAIT_VERB: &str = "vault.jobs.orders.wait";
/// `vault.machines.place`.
pub const MACHINES_PLACE_VERB: &str = "vault.machines.place";
/// `vault.jobs.logs.tail`.
pub const LOGS_TAIL_VERB: &str = "vault.jobs.logs.tail";

/// Takes the erased actor out of every order they made or cancelled (the side table's actor
/// scrub). An order whose requester is erased has no authority left: the loop cancels it at its
/// next pass. The scrub bumps each row's revision, so a pass that read the row before loses its
/// write and never puts the actor back.
pub(crate) fn erase_order_actor_in_txn(
    vault: &Vault,
    wtxn: &mut heed::RwTxn<'_>,
    actor: &EntityId,
) -> crate::Result<()> {
    for (id, mut order) in record::WORK_ORDERS.scan(&vault.store, wtxn)? {
        let mut changed = false;
        match &mut order.ordered_by {
            OrderedBy::Owner { owner } if *owner == Some(*actor) => {
                *owner = None;
                changed = true;
            }
            OrderedBy::Agent { actor: by, .. } if *by == Some(*actor) => {
                *by = None;
                changed = true;
            }
            _ => {}
        }
        if let Some(cancel) = &mut order.cancel
            && cancel.by == Some(*actor)
        {
            cancel.by = None;
            changed = true;
        }
        if let OrderState::Cancelled {
            why: CancelWhy::Asked { by },
        } = &mut order.state
            && *by == Some(*actor)
        {
            *by = None;
            changed = true;
        }
        if changed {
            order.revision += 1;
            record::WORK_ORDERS.put(&vault.store, wtxn, &id, &order)?;
            vault.erase_order_wait_replies_in_txn(wtxn, &id)?;
        }
    }
    Ok(())
}
