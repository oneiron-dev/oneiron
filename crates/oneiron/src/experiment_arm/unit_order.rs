//! A waiting line unit (pass 34, 1.1; row H3): `vault.arms.units.reserve` with a wait other
//! than `no` makes a work order charged to the unit's line, and the order loop reserves the
//! unit when it can run. The order holds nothing while it waits: no claim, no draw, no seconds
//! of the line's pools.
//!
//! Attempt `n` of the order is two writes. The first ([`Vault::reserve_order_attempt`]) checks
//! the order as the loop read it, reserves the unit through the line's reserve for the order's
//! requester, under the claim key (arm, rung, the order id in hex, `n`) and the job id the order
//! and `n` fix ([`attempt_job_id`]), and writes the order's attempt entry beside the claim. The
//! second is the built claimed start ([`Vault::start_claimed_gpu_job`] with
//! `GpuJobActor::Order`): the job row and the claim's `Claimed -> Started`. A claim that never
//! starts is released by custody (pass 32, 5.2), and the loop reads the release as the attempt's
//! end. `wait: no` is the reserve itself ([`super::unit_reserve_as`]), unchanged.

use serde::{Deserialize, Serialize};

use crate::consent::AuthenticatedOwner;
use crate::gpu_line::doors_caller::LineCaller;
use crate::gpu_line::{IntentAsk, IntentRefused, IntentStand, line_in_txn};
use crate::memory::verb_grant_caller::VerbGrantCaller;
use crate::memory::{
    MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_BUDGET_SPENT, MEMORY_CODE_FORBIDDEN,
    MEMORY_CODE_NOT_FOUND, Memory, MemoryError, MemoryResult,
};
use crate::work_order::{
    AttemptRefused, AttemptToMake, Blocker, OrderCharge, OrderClass, OrderLimits, OrderStarter,
    OrderState, OrderWishes, OrderedBy, ResultBinding, WaitRule, WorkOrder, WorkOrderView,
    attempt_job_id,
};
use crate::{EntityId, Vault};

use super::reserve::{
    ARMS_UNITS_RESERVE_VERB, UnitReserveRequest, invalid_state, not_found,
    reserve_for_caller_in_txn, role_for,
};
use super::unit_terms::{check_contract_and_workload, check_offer_and_machine};
use super::unit_view::UnitView;

/// The prefix of the intent key a work order's attempt reserves under; the order id in hex and
/// the attempt number follow it.
const ATTEMPT_INTENT_PREFIX: &str = "work-order-attempt:";

/// What `vault.arms.units.reserve` answers: the unit, for `wait: no`; the work order that
/// reserves it, for any other wait. Untagged, so a `wait: no` answer keeps its wire shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum UnitReserveAnswer {
    /// The unit as its reserve and its start left it.
    Unit(UnitView),
    /// The work order that waits, holding nothing, and reserves the unit when it can run.
    Order(Box<WorkOrderView>),
}

/// `vault.arms.units.reserve` with a wait (`open`, or `until` a time): `memory`'s caller orders
/// the unit `request` names at `now_ms`, as a work order that holds nothing until the loop
/// reserves it. The caller is judged as the reserve judges it: the line cover, then the lead
/// role (the reviewer role for a review check). The ask's fixed terms are checked now, as the
/// reserve checks them: the arm is the line's, the contract is the arm's pin, the workload's pin
/// carries the contract and the code revision, the seconds are its maximum, the offer is the
/// line's, and a named machine is one of the line's. The rung's state, the forecast, the
/// family's cap, the room and the approval are read when the attempt is made. The order may run
/// on the named machine, or else on the line's machines as they stand now. The unit's claims
/// take the order id as their unit key and the attempt number as their attempt, so the ask's
/// `unit_key` and `attempt` name the call only. The same intent key, ask and wait answer the
/// order it made, `replayed: true`.
///
/// # Errors
///
/// `bad_request` for a malformed ask, `wait: no` (the reserve answers it) or a `wait.until`
/// that is not after now; `forbidden` and `not_found` as the reserve answers them;
/// `invalid_state` for a fixed term the line refuses (`contract_changed`, `workload_mismatch`,
/// `maximum_mismatch`, `offer_not_managed`, `machine_not_allowed`), a line that names no machine
/// (`no_machine`), an intent key an immediate reserve holds (`intent_key_reserved`) or another
/// ask or wait under the same key; a store failure.
pub fn unit_order_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &UnitReserveRequest,
    now_ms: u64,
) -> MemoryResult<WorkOrderView> {
    request.check_shape()?;
    match request.wait {
        WaitRule::No => {
            return Err(MemoryError::new(
                MEMORY_CODE_BAD_REQUEST,
                "wait: `no` reserves the unit at once; vault.arms.units.reserve answers it",
                &["Send the ask with wait open, or until a time, to order the unit."],
            ));
        }
        WaitRule::Until { ms } if ms <= now_ms => {
            return Err(MemoryError::new(
                MEMORY_CODE_BAD_REQUEST,
                "wait.until is a time after now",
                &["Correct the ask and send it again."],
            ));
        }
        WaitRule::Until { .. } | WaitRule::Open => {}
    }
    let _ = super::unit_result::check_result_binding(memory, request.result.as_ref());
    let vault = memory.vault();
    vault.try_with_write_txn_grouped(|txn| {
        order_unit_in_txn(vault, txn, memory, owner, request, now_ms)
    })
}

/// The answer of `vault.arms.units.reserve` for a waiting unit once the server's pass ran over
/// its new order: order `order` of line `line` read again, as `memory`'s caller, who made it,
/// reads it. The caller is judged on the reserve's own verb over the line, as the reserve
/// judges it, so an agent whose Grant names the reserve and not `vault.jobs.order` reads its
/// own unit's order. `None` when the order is gone, is not the caller's, or is not charged to
/// `line`.
///
/// # Errors
///
/// `forbidden` for a caller the reserve no longer admits over the line; a store failure.
pub fn unit_ordered_view_as(
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    line: EntityId,
    order: &EntityId,
) -> MemoryResult<Option<WorkOrderView>> {
    let vault = memory.vault();
    let txn = vault.store.env.read_txn().map_err(crate::Error::from)?;
    let caller =
        memory.verb_grant_caller_admits_over_in_txn(&txn, owner, ARMS_UNITS_RESERVE_VERB, line)?;
    Ok(vault
        .reached_work_order_view_in_txn(&txn, caller, order)?
        .filter(|view| {
            matches!(view.order.charge, OrderCharge::Line { line: charged, .. } if charged == line)
        }))
}

fn order_unit_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    memory: &Memory<'_>,
    owner: Option<&AuthenticatedOwner>,
    request: &UnitReserveRequest,
    now_ms: u64,
) -> MemoryResult<WorkOrderView> {
    let caller = memory.verb_grant_caller_admits_over_in_txn(
        txn,
        owner,
        ARMS_UNITS_RESERVE_VERB,
        request.line,
    )?;
    let asker = memory.actor();
    let line = line_in_txn(vault, txn, &request.line)?
        .ok_or_else(|| not_found("no GPU line is set for this project"))?;
    let line_caller = match caller {
        VerbGrantCaller::Owner => LineCaller::Owner(asker),
        VerbGrantCaller::Agent { grant, .. } => LineCaller::Agent { grant },
    };
    line_caller.require_role(&line, &[role_for(request.purpose)], ARMS_UNITS_RESERVE_VERB)?;

    // The intent key: the same ask answers its order again; an immediate reserve's key is not
    // reused for a waiting unit.
    let intent = IntentAsk::new(
        asker,
        ARMS_UNITS_RESERVE_VERB,
        &request.intent_key,
        &request.ask(),
    )?;
    if let IntentStand::Replayed(written) = intent.stand_in_txn(vault, txn)?? {
        let order = match <[u8; 16]>::try_from(written.as_slice()) {
            Ok(bytes) => match EntityId::from_bytes(bytes) {
                Ok(id) => vault.work_order_in_txn(txn, &id)?,
                Err(_) => None,
            },
            Err(_) => {
                return Err(invalid_state(
                    "intent_key_reserved: an immediate reserve holds this intent key; read its unit with vault.arms.get, or use a new key",
                ));
            }
        }
        .ok_or_else(|| not_found("the work order this intent key made is gone"))?;
        // The ask's digest leaves the wait out (an order's attempts reserve with `wait: no`),
        // so the order's own wait tells a repeat from another ask under the key.
        if order.wait != request.wait {
            return Err(IntentRefused::DifferentAsk.into());
        }
        return Ok(vault.work_order_view_as_in_txn(txn, caller, order, true)?);
    }

    let arm = vault
        .experiment_arm_in_txn(txn, &request.arm)?
        .filter(|arm| arm.line == request.line)
        .ok_or_else(|| not_found("no experiment arm of this line has this id"))?;
    let workload = check_contract_and_workload(vault, txn, request, &arm)?;
    check_offer_and_machine(request, &line)?;
    let machines = match request.machine {
        Some(machine) => vec![machine],
        None => line.machines.clone(),
    };
    if machines.is_empty() {
        return Err(invalid_state(
            "no_machine: the line names no machine; a waiting unit runs on one of the line's machines",
        ));
    }

    let order = WorkOrder {
        id: EntityId::now(),
        ordered_by: match caller {
            VerbGrantCaller::Owner => OrderedBy::Owner { owner: Some(asker) },
            VerbGrantCaller::Agent { actor, grant } => OrderedBy::Agent {
                actor: Some(actor),
                class: memory.actor_class(),
                grant,
            },
        },
        workload: request.workload.clone(),
        request: workload.pin.request,
        charge: OrderCharge::Line {
            arm: arm.id,
            rung: request.rung,
            line: request.line,
            offer: request.offer.clone(),
            purpose: request.purpose,
        },
        limits: OrderLimits {
            machines,
            ..OrderLimits::default()
        },
        wishes: OrderWishes::default(),
        class: OrderClass::default(),
        wait: request.wait,
        retry_on: Vec::new(),
        state: OrderState::Open {
            blocked: Vec::new(),
            looked_at_ms: now_ms,
            earliest_ms: None,
        },
        cancel: None,
        retry_not_before_ms: None,
        attempts: Vec::new(),
        // The order's result is the unit's: each attempt's reserve writes it onto its claim.
        result: request.result.map(|binding| ResultBinding {
            artifact: binding.artifact,
            task: binding.task,
        }),
        intent_key: Some(request.intent_key.clone()),
        after: None,
        group: None,
        ordered_at_ms: now_ms,
        updated_at_ms: now_ms,
        revision: 0,
    };
    vault.put_new_work_order_in_txn(txn, &order)?;
    intent.keep_in_txn(vault, txn, order.id.as_bytes().to_vec(), now_ms)?;
    Ok(vault.work_order_view_as_in_txn(txn, caller, order, false)?)
}

/// Why the attempt's write wrote nothing.
enum AttemptWrite {
    Refused(AttemptRefused),
    Store(crate::Error),
}

impl From<crate::Error> for AttemptWrite {
    fn from(error: crate::Error) -> Self {
        Self::Store(error)
    }
}

impl Vault {
    /// Makes attempt `attempt.n` of a line unit's work order (row H3) in one write: the order
    /// is checked as the loop read it (its revision, its turn, no cancel, its wait, its
    /// requester's authority and the workload's approval on the placed machine, as the built
    /// start checks an offer's attempt); the line's reserve claims the unit for the order's
    /// requester on that machine, under the claim key (arm, rung, the order id in hex, `n`) and
    /// the job id [`attempt_job_id`] fixes; and the order's attempt entry is written beside the
    /// claim, the order `Running`. Any refusal writes nothing: no claim, no draw, no
    /// `GPU_LINE_REFUSAL` row (the order's blockers say why it waits), no attempt. The claim's job
    /// is then started with [`Vault::start_claimed_gpu_job`] under `GpuJobActor::Order`.
    ///
    /// # Errors
    ///
    /// Storage errors. Every refusal is the inner `Err`: `OrderChanged` when the order is not as
    /// the loop read it, else the blocker the reserve's refusal maps onto (EM-19, the reserve's
    /// code kept in its reason).
    pub fn reserve_order_attempt(
        &self,
        attempt: &AttemptToMake<'_>,
        now_ms: u64,
    ) -> crate::Result<Result<UnitView, AttemptRefused>> {
        let order = attempt.order;
        let OrderCharge::Line {
            arm,
            rung,
            line,
            offer,
            purpose,
        } = &order.charge
        else {
            return Ok(Err(AttemptRefused::OrderChanged));
        };
        let job = attempt_job_id(&order.id, attempt.n)?;
        let request = UnitReserveRequest {
            intent_key: format!("{ATTEMPT_INTENT_PREFIX}{}:{}", order.id.to_hex(), attempt.n),
            line: *line,
            arm: *arm,
            rung: *rung,
            unit_key: order.id.to_hex(),
            attempt: attempt.n,
            purpose: *purpose,
            offer: offer.clone(),
            workload: order.workload.clone(),
            machine: Some(attempt.machine),
            code_sha: attempt.pin.commit.clone(),
            contract_sha256: attempt.pin.contract_sha256.clone(),
            secs: order.request.maximum_secs,
            result: order
                .result
                .map(|binding| crate::gpu_job::GpuJobResultBinding {
                    artifact: binding.artifact,
                    task: binding.task,
                }),
            wait: WaitRule::No,
        };
        let reference = attempt.reference();
        let made = self.try_with_write_txn_grouped(|txn| -> Result<UnitView, AttemptWrite> {
            let starter = match self.order_starter_in_txn(txn, &reference, &job, now_ms)? {
                Ok(starter) => starter,
                Err(refused) => return Err(AttemptWrite::Refused(refused)),
            };
            let (caller, asker) = match starter {
                OrderStarter::Owner { owner, .. } => (LineCaller::Owner(owner), owner),
                OrderStarter::Agent { actor, grant } => (LineCaller::Agent { grant }, actor),
            };
            let view = match reserve_for_caller_in_txn(
                self,
                txn,
                caller,
                asker,
                &request,
                Some(job),
                now_ms,
            ) {
                Ok(Ok(view)) => view,
                Ok(Err(refusal)) | Err(refusal) => {
                    return Err(AttemptWrite::Refused(AttemptRefused::Blocked(
                        blocker_of_reserve(&refusal, request.secs),
                    )));
                }
            };
            match self.record_order_attempt_in_txn(txn, &reference, &job, now_ms)? {
                Ok(_) => Ok(view),
                Err(refused) => Err(AttemptWrite::Refused(refused)),
            }
        });
        match made {
            Ok(view) => Ok(Ok(view)),
            Err(AttemptWrite::Refused(refused)) => Ok(Err(refused)),
            Err(AttemptWrite::Store(error)) => Err(error),
        }
    }
}

/// The blocker a line reserve's refusal maps onto (EM-19): a budget refusal is the line's room;
/// a caller the line no longer admits has no live authority; the family's running cap is a full
/// cap; every other refusal keeps the reserve's message, its code first, as `line_refuses` when
/// waiting does not clear it and `line_not_ready` when it does.
fn blocker_of_reserve(refusal: &MemoryError, secs: u64) -> Blocker {
    let code = refusal
        .message
        .split_once(':')
        .map_or(refusal.message.as_str(), |(code, _)| code)
        .trim();
    match refusal.code.as_str() {
        MEMORY_CODE_BUDGET_SPENT => {
            return Blocker::LineRoom {
                pool: code.to_owned(),
                short_secs: secs,
            };
        }
        MEMORY_CODE_FORBIDDEN => return Blocker::GrantNotLive,
        MEMORY_CODE_NOT_FOUND => {
            return Blocker::LineRefuses {
                reason: refusal.message.clone(),
            };
        }
        _ => {}
    }
    match code {
        "family_running_cap" => Blocker::CapFull {
            cap: code.to_owned(),
            running: first_number(&refusal.message),
        },
        "arm_closed"
        | "rung_closed"
        | "new_idea_rung_one_only"
        | "contract_changed"
        | "workload_mismatch"
        | "maximum_mismatch"
        | "offer_not_managed"
        | "machine_not_allowed"
        | "over_review_check"
        | "attempt_conflict"
        | "attempt_not_next" => Blocker::LineRefuses {
            reason: refusal.message.clone(),
        },
        _ => Blocker::LineNotReady {
            reason: refusal.message.clone(),
        },
    }
}

/// The first number in `message`: the cap the reserve's `family_running_cap` names.
fn first_number(message: &str) -> u32 {
    message
        .split(|c: char| !c.is_ascii_digit())
        .find(|part| !part.is_empty())
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0)
}
