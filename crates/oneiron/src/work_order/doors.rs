//! The work order doors (pass 34, 1.1 and 14): `vault.jobs.order`, `vault.jobs.orders.get`,
//! `.list` and `.cancel`, and the read `vault.machines.place`. Each proves `verb_grant_caller`:
//! the owner under his own proof, or an agent whose own live Grant from a live owner lists the
//! verb, judged again in the door's own read or write. The charge decides what else is checked,
//! when an attempt is made: an offer's allowance, in the built start, so an agent's offer order
//! is made under the Grant that starts its GPU jobs. `.get` and `.list` show an agent its own
//! orders, with no other order's id, and the owner every order; `.cancel` follows the built
//! rule for jobs: the owner cancels any order, an agent only one it made.
use crate::consent::AuthenticatedOwner;
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MEMORY_CODE_INVALID_STATE,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::{EntityId, Vault};

use super::blocker::Blocker;
use super::caps::{RunningCaps, caps_problem};
use super::fit::{MachineFacts, scope_allowed};
use super::group::{admit_group_member_in_txn, replay_is_same_member_in_txn};
use super::pass::OrderFit;
use super::place::place;
use super::record::{
    CancelAsk, CancelWhy, OrderCharge, OrderState, OrderedBy, WORK_ORDERS, WaitRule, WorkOrder,
};

/// Why a cancel's write changed nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelRefused {
    NotFound,
    /// The order is at an end.
    Ended,
}
use super::upstream::admit_after_in_txn;
use super::wire::{
    MachinesPlaceRequest, MachinesPlaceView, WorkOrderList, WorkOrderListRequest, WorkOrderRef,
    WorkOrderRequest, WorkOrderView,
};
use super::{
    MACHINES_PLACE_VERB, ORDER_VERB, ORDERS_CANCEL_VERB, ORDERS_GET_VERB, ORDERS_LIST_VERB,
};

/// The most bytes an intent key holds.
pub const ORDER_INTENT_KEY_MAX: usize = 128;

/// A refusal with `code` whose reasons are `blockers`, by their codes (14.4).
#[must_use]
pub fn order_refusal(code: &str, message: &str, blockers: &[Blocker]) -> MemoryError {
    let mut error = MemoryError::new(
        code,
        message.to_owned(),
        &["Read the reason codes; vault.machines.place shows where the work could run."],
    );
    error.reason_codes = blockers
        .iter()
        .map(|blocker| blocker.code().to_owned())
        .collect();
    error
}

fn bad_request(message: &str) -> MemoryError {
    MemoryError::new(MEMORY_CODE_BAD_REQUEST, message.to_owned(), &[])
}

fn is_lower_hex_64(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Who ordered, as the door admitted the caller.
fn ordered_by(memory: &Memory<'_>, caller: VerbGrantCaller) -> OrderedBy {
    match caller {
        VerbGrantCaller::Owner => OrderedBy::Owner {
            owner: Some(memory.actor()),
        },
        VerbGrantCaller::Agent { actor, grant } => OrderedBy::Agent {
            actor: Some(actor),
            class: memory.actor_class(),
            grant,
        },
    }
}

/// `order` as `caller` reads it. An attempt's RANK decision lists the orders that were
/// runnable in its pass, which may be other callers' orders: an agent sees only its own order's
/// id among the options, and the owner sees the whole decision.
pub(super) fn order_seen_by(caller: VerbGrantCaller, order: WorkOrder) -> WorkOrder {
    match caller {
        VerbGrantCaller::Owner => order,
        VerbGrantCaller::Agent { .. } => only_own_rank_option(order),
    }
}

/// `order` as its requester reads it: what a settled `vault.jobs.orders.wait` freezes for the
/// runs parked on it (the owner reads the same answer).
pub(super) fn seen_by_requester(order: WorkOrder) -> WorkOrder {
    match order.ordered_by {
        OrderedBy::Owner { .. } => order,
        OrderedBy::Agent { .. } => only_own_rank_option(order),
    }
}

/// `order` with only its own id among each attempt's RANK options.
fn only_own_rank_option(mut order: WorkOrder) -> WorkOrder {
    let own = order.id.to_hex();
    for attempt in &mut order.attempts {
        attempt.ranked.options.retain(|option| *option == own);
    }
    order
}

/// Whether `caller` may read or cancel `order`: the owner any, an agent one it made.
pub(super) fn reaches(caller: VerbGrantCaller, order: &WorkOrder) -> bool {
    match caller {
        VerbGrantCaller::Owner => true,
        VerbGrantCaller::Agent { actor, .. } => order.ordered_by.actor() == Some(actor),
    }
}

/// Whether `order` was made from the same request as `input` by the same caller, but for its
/// group, which [`replay_is_same_member_in_txn`] reads.
fn same_request(order: &WorkOrder, input: &WorkOrderRequest, by: &OrderedBy) -> bool {
    order.ordered_by.actor() == by.actor()
        && order.workload == input.workload
        && order.charge == input.charge
        && order.limits == input.limits
        && order.wishes == input.wishes
        && order.class == input.class
        && order.wait == input.wait
        && order.retry_on == input.retry_on
        && order.result == input.result
        && order.after == input.after
}

/// `vault.jobs.order`: `memory`'s caller orders one pinned workload at `now_ms`. The order is
/// written open, holding nothing; the loop places it.
///
/// # Errors
///
/// `forbidden` for a caller the verb does not admit; `bad_request` for a malformed request;
/// `invalid_state` with the reason `workload_unknown` for a digest nothing pinned, or an intent
/// key reused with another input.
pub fn order_work_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &WorkOrderRequest,
    now_ms: u64,
) -> MemoryResult<WorkOrderView> {
    if !is_lower_hex_64(&input.workload) {
        return Err(bad_request(
            "workload is a digest of 64 lower-hex characters",
        ));
    }
    match &input.charge {
        OrderCharge::Offer { name } if name.is_empty() => {
            return Err(bad_request("an offer charge names its offer"));
        }
        OrderCharge::Offer { .. } => {}
        OrderCharge::Line { .. } => {
            return Err(bad_request(
                "a line unit is ordered with vault.arms.units.reserve, which writes its claim",
            ));
        }
    }
    if input
        .intent_key
        .as_ref()
        .is_some_and(|key| key.is_empty() || key.len() > ORDER_INTENT_KEY_MAX)
    {
        return Err(bad_request(&format!(
            "intent_key holds 1 to {ORDER_INTENT_KEY_MAX} bytes"
        )));
    }
    if let WaitRule::Until { ms } = input.wait
        && ms <= now_ms
    {
        return Err(bad_request("wait.until is a time after now"));
    }
    if let Some(problem) = caps_problem(&input.limits.caps) {
        return Err(bad_request(&problem));
    }
    let vault = memory.vault();
    vault
        .with_write_txn_grouped(|txn| -> crate::Result<MemoryResult<WorkOrderView>> {
            let caller = match memory.verb_grant_caller_admits_in_txn(txn, owner, ORDER_VERB) {
                Ok(caller) => caller,
                Err(refused) => return Ok(Err(refused)),
            };
            let by = ordered_by(memory, caller);
            if let Some(key) = &input.intent_key {
                let earlier = WORK_ORDERS
                    .scan(&vault.store, txn)?
                    .into_iter()
                    .map(|(_, order)| order)
                    .find(|order| {
                        order.intent_key.as_ref() == Some(key)
                            && order.ordered_by.actor() == by.actor()
                    });
                if let Some(order) = earlier {
                    if same_request(&order, input, &by)
                        && replay_is_same_member_in_txn(vault, txn, &order, input.group.as_ref())?
                    {
                        let view =
                            vault.order_view_in_txn(txn, order_seen_by(caller, order), true)?;
                        return Ok(Ok(view));
                    }
                    return Ok(Err(MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        "this intent key made another order; use a new key for new work",
                        &["Read the order this key made with vault.jobs.orders.list."],
                    )));
                }
            }
            let Some(row) = vault.job_workload_in_txn(txn, &input.workload)? else {
                return Ok(Err(order_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "no workload is pinned under this digest",
                    &[Blocker::WorkloadUnknown],
                )));
            };
            if let Some(after) = &input.after
                && let Err(refused) = admit_after_in_txn(vault, txn, after, caller)?
            {
                return Ok(Err(refused));
            }
            // A group the request starts takes the order's id.
            let id = EntityId::now();
            let (member, new_group) = match &input.group {
                Some(request) => {
                    match admit_group_member_in_txn(vault, txn, request, id, &by, caller, now_ms)? {
                        Ok((member, row)) => (Some(member), row),
                        Err(refused) => return Ok(Err(refused)),
                    }
                }
                None => (None, None),
            };
            let order = WorkOrder {
                id,
                ordered_by: by,
                workload: input.workload.clone(),
                request: row.pin.request,
                charge: input.charge.clone(),
                limits: input.limits.clone(),
                wishes: input.wishes.clone(),
                class: input.class,
                wait: input.wait,
                retry_on: input.retry_on.clone(),
                state: OrderState::Open {
                    blocked: Vec::new(),
                    looked_at_ms: now_ms,
                    earliest_ms: None,
                },
                cancel: None,
                retry_not_before_ms: None,
                attempts: Vec::new(),
                result: input.result,
                intent_key: input.intent_key.clone(),
                after: input.after,
                group: member,
                ordered_at_ms: now_ms,
                updated_at_ms: now_ms,
                revision: 0,
            };
            if !scope_allowed(&order.limits, &row.pin.scope) {
                return Ok(Err(order_refusal(
                    MEMORY_CODE_INVALID_STATE,
                    "the order's limits allow no scope of the kind the workload's pin runs in",
                    &[Blocker::scope_not_allowed(&row.pin.scope)],
                )));
            }
            // The loop and the start ask the same question at each attempt.
            if vault.order_authority_in_txn(txn, &order)?.is_none() {
                return Ok(Err(order_refusal(
                    MEMORY_CODE_FORBIDDEN,
                    "an agent's offer order is made under the Grant that starts its GPU jobs: \
                     the Grant that admits it to vault.jobs.order must be the one that admits it \
                     to vault.gpu.jobs.start, with the owner's per-job maximum beside it",
                    &[Blocker::GrantNotLive],
                )));
            }
            WORK_ORDERS.put(&vault.store, txn, &order.id, &order)?;
            if let Some(group) = &new_group {
                vault.put_work_order_group_in_txn(txn, group)?;
            }
            Ok(Ok(WorkOrderView {
                order,
                replayed: false,
                receipt: None,
            }))
        })
        .map_err(MemoryError::from)?
}

/// The answer of `vault.jobs.order` once the server's pass ran over the new order: `order`
/// read again and seen as `memory`'s caller, who made it, reads it. An agent sees only its own
/// order's id in the RANK decision of the attempt the pass made, as every read answers it.
/// `None` when the order is gone.
///
/// # Errors
///
/// `forbidden` for a caller the verb does not admit.
pub fn ordered_view_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    order: &EntityId,
) -> MemoryResult<Option<WorkOrderView>> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let caller = memory.verb_grant_caller_admits_in_txn(&txn, owner, ORDER_VERB)?;
    match WORK_ORDERS.get(&vault.store, &txn, order)? {
        Some(order) if reaches(caller, &order) => Ok(Some(vault.order_view_in_txn(
            &txn,
            order_seen_by(caller, order),
            false,
        )?)),
        _ => Ok(None),
    }
}

/// `vault.jobs.orders.get`: one order, as `memory`'s caller may read it.
///
/// # Errors
///
/// `forbidden` for a caller the verb does not admit; `not_found` for an order the caller may
/// not read or that does not exist (the two answer alike).
pub fn work_order_get_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &WorkOrderRef,
) -> MemoryResult<WorkOrderView> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let caller = memory.verb_grant_caller_admits_in_txn(&txn, owner, ORDERS_GET_VERB)?;
    match WORK_ORDERS.get(&vault.store, &txn, &input.order)? {
        Some(order) if reaches(caller, &order) => {
            Ok(vault.order_view_in_txn(&txn, order_seen_by(caller, order), false)?)
        }
        _ => Err(MemoryError::new(
            MEMORY_CODE_NOT_FOUND,
            "no such work order",
            &["List the orders you may read with vault.jobs.orders.list."],
        )),
    }
}

/// `vault.jobs.orders.list`: the orders `memory`'s caller may read, newest first.
///
/// # Errors
///
/// `forbidden` for a caller the verb does not admit.
pub fn work_order_list_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &WorkOrderListRequest,
) -> MemoryResult<WorkOrderList> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let caller = memory.verb_grant_caller_admits_in_txn(&txn, owner, ORDERS_LIST_VERB)?;
    let mut orders: Vec<WorkOrder> = WORK_ORDERS
        .scan(&vault.store, &txn)?
        .into_iter()
        .map(|(_, order)| order)
        .filter(|order| reaches(caller, order))
        .filter(|order| !input.open_only || !order.state.is_terminal())
        .map(|order| order_seen_by(caller, order))
        .collect();
    orders.sort_by(|a, b| b.ordered_at_ms.cmp(&a.ordered_at_ms).then(b.id.cmp(&a.id)));
    Ok(WorkOrderList { orders })
}

/// `vault.jobs.orders.cancel`: `memory`'s caller cancels one order at `now_ms`. An open order
/// is cancelled at once and is never dispatched; a running one has its attempt stopped and is
/// cancelled when that attempt's end is in. A cancel and a dispatch compare the order's
/// revision, so they never both win.
///
/// # Errors
///
/// `forbidden` for a caller the verb does not admit or an agent's order it did not make;
/// `not_found` for an unknown order; `invalid_state` for an order at an end.
pub fn work_order_cancel_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &WorkOrderRef,
    now_ms: u64,
) -> MemoryResult<WorkOrderView> {
    let vault = memory.vault();
    vault
        .with_write_txn_grouped(|txn| -> crate::Result<MemoryResult<WorkOrderView>> {
            let caller =
                match memory.verb_grant_caller_admits_in_txn(txn, owner, ORDERS_CANCEL_VERB) {
                    Ok(caller) => caller,
                    Err(refused) => return Ok(Err(refused)),
                };
            let Some(order) = WORK_ORDERS.get(&vault.store, txn, &input.order)? else {
                return Ok(Err(MemoryError::new(
                    MEMORY_CODE_NOT_FOUND,
                    "no such work order",
                    &["List the orders you may read with vault.jobs.orders.list."],
                )));
            };
            if !reaches(caller, &order) {
                return Ok(Err(MemoryError::new(
                    MEMORY_CODE_FORBIDDEN,
                    "an agent cancels only a work order it made",
                    &["Ask the vault owner to cancel it."],
                )));
            }
            let cancelled =
                vault.cancel_work_order_in_txn(txn, &order.id, Some(memory.actor()), now_ms)?;
            let order = match cancelled {
                Ok(order) => order,
                Err(CancelRefused::NotFound) => {
                    return Ok(Err(MemoryError::new(
                        MEMORY_CODE_NOT_FOUND,
                        "no such work order",
                        &[],
                    )));
                }
                Err(CancelRefused::Ended) => {
                    return Ok(Err(MemoryError::new(
                        MEMORY_CODE_INVALID_STATE,
                        "the work order has ended",
                        &["Read its end with vault.jobs.orders.get."],
                    )));
                }
            };
            Ok(Ok(vault.order_view_in_txn(
                txn,
                order_seen_by(caller, order),
                false,
            )?))
        })
        .map_err(MemoryError::from)?
}

/// `vault.machines.place`: where an order of `input` by `memory`'s caller would run now, over
/// the facts `machines`, with each other machine's reasons. It starts nothing.
///
/// The order it reads is made under the Grant `vault.jobs.order` would record for the caller,
/// never the Grant that admits the read: an agent may hold the two verbs in two Grants.
///
/// # Errors
///
/// `forbidden` for a caller the verb does not admit, or that `vault.jobs.order` would not
/// admit; `bad_request` for a malformed digest.
pub fn machines_place_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    input: &MachinesPlaceRequest,
    machines: &[MachineFacts],
    now_ms: u64,
) -> MemoryResult<MachinesPlaceView> {
    if !is_lower_hex_64(&input.workload) {
        return Err(bad_request(
            "workload is a digest of 64 lower-hex characters",
        ));
    }
    if let Some(problem) = caps_problem(&input.limits.caps) {
        return Err(bad_request(&problem));
    }
    let vault: &Vault = memory.vault();
    let caller = {
        let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
        memory.verb_grant_caller_admits_in_txn(&txn, owner, MACHINES_PLACE_VERB)?;
        memory.verb_grant_caller_admits_in_txn(&txn, owner, ORDER_VERB)?
    };
    let Some(row) = vault.job_workload(&input.workload)? else {
        return Err(order_refusal(
            MEMORY_CODE_INVALID_STATE,
            "no workload is pinned under this digest",
            &[Blocker::WorkloadUnknown],
        ));
    };
    // The order this request would make, never written.
    let order = WorkOrder {
        id: EntityId::now(),
        ordered_by: ordered_by(memory, caller),
        workload: input.workload.clone(),
        request: row.pin.request,
        charge: OrderCharge::Offer {
            name: String::new(),
        },
        limits: input.limits.clone(),
        wishes: input.wishes.clone(),
        class: Default::default(),
        wait: WaitRule::Open,
        retry_on: Vec::new(),
        state: OrderState::Open {
            blocked: Vec::new(),
            looked_at_ms: now_ms,
            earliest_ms: None,
        },
        cancel: None,
        retry_not_before_ms: None,
        attempts: Vec::new(),
        result: None,
        intent_key: None,
        after: None,
        group: None,
        ordered_at_ms: now_ms,
        updated_at_ms: now_ms,
        revision: 0,
    };
    let running = RunningCaps::of(&vault.work_orders()?);
    match vault.order_fit(&order, machines, &running, now_ms)? {
        OrderFit::Runnable { candidates, .. } => {
            let facts: Vec<&MachineFacts> = machines
                .iter()
                .filter(|facts| candidates.contains(&facts.machine))
                .collect();
            let decision = place(&order, &facts).map(|(_, decision)| decision);
            let ordered = decision
                .as_ref()
                .map(|decision| {
                    decision
                        .options
                        .iter()
                        .filter_map(|hex| EntityId::from_hex(hex).ok())
                        .collect()
                })
                .unwrap_or(candidates);
            Ok(MachinesPlaceView {
                candidates: ordered,
                blocked: Vec::new(),
                decision,
            })
        }
        OrderFit::Blocked(blocked) => Ok(MachinesPlaceView {
            candidates: Vec::new(),
            blocked,
            decision: None,
        }),
        // The read's order waits openly, so its wait never runs out, and it waits on no order.
        OrderFit::WaitEnded | OrderFit::UpstreamEnded(_) => Ok(MachinesPlaceView {
            candidates: Vec::new(),
            blocked: Vec::new(),
            decision: None,
        }),
        OrderFit::AuthorityEnded => Err(order_refusal(
            MEMORY_CODE_FORBIDDEN,
            "the caller's authority to order this work has ended",
            &[Blocker::GrantNotLive],
        )),
    }
}

impl Vault {
    /// The cancel's write, in `txn`: an open order with no attempt in flight is cancelled at
    /// once and is never dispatched. An order whose last attempt has no end, running or open
    /// while that attempt is unconfirmed, keeps its state with the cancel recorded: the loop
    /// stops the attempt it can reach, and the order is cancelled when the attempt's end (its
    /// receipt or the owner's write-off) is in. The write bumps the order's revision, so a
    /// dispatch that read the order before refuses in its own write.
    ///
    /// # Errors
    ///
    /// Storage errors. Every refusal is the inner `Err`.
    pub fn cancel_work_order_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        by: Option<EntityId>,
        now_ms: u64,
    ) -> crate::Result<Result<WorkOrder, CancelRefused>> {
        let Some(mut order) = WORK_ORDERS.get(&self.store, txn, id)? else {
            return Ok(Err(CancelRefused::NotFound));
        };
        let attempt_in_flight = order.last_attempt().is_some_and(|last| last.end.is_none());
        match order.state {
            OrderState::Open { .. } if !attempt_in_flight => {
                order.state = OrderState::Cancelled {
                    why: CancelWhy::Asked { by },
                };
            }
            OrderState::Open { .. } | OrderState::Running { .. } => {
                if order.cancel.is_none() {
                    order.cancel = Some(CancelAsk { at_ms: now_ms, by });
                }
            }
            OrderState::Done | OrderState::GivenUp { .. } | OrderState::Cancelled { .. } => {
                return Ok(Err(CancelRefused::Ended));
            }
        }
        // The row was read in this write, so it is at its stored revision.
        self.put_work_order_in_txn(txn, &mut order, now_ms)?;
        Ok(Ok(order))
    }

    /// [`Self::cancel_work_order_in_txn`] in its own write.
    ///
    /// # Errors
    ///
    /// Storage errors. Every refusal is the inner `Err`.
    pub fn cancel_work_order(
        &self,
        id: &EntityId,
        by: Option<EntityId>,
        now_ms: u64,
    ) -> crate::Result<Result<WorkOrder, CancelRefused>> {
        self.with_write_txn_grouped(|txn| self.cancel_work_order_in_txn(txn, id, by, now_ms))
    }
}
