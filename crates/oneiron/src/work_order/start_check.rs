//! What the built start and cancel check of an order's attempt in their own read and write
//! (pass 34, 1.1; hunk H1 of row Q1): the order is as the loop read it, its requester's
//! authority lives, the workload's approval covers the machine, and the attempt is the order's
//! next one under the job id the order fixes. The loop's fit asks the same authority question
//! ([`Vault::order_authority_in_txn`]), so a pass and the start's write never disagree on it.
use crate::authority::principal_standing_covering_or_lapse_in_txn;
use crate::experiment_arm::{ARMS_UNITS_RESERVE_VERB, role_for};
use crate::federation::{FederationGrant, agent_grants_for_store_in_txn};
use crate::gpu_job::GpuJobVerb;
use crate::gpu_line::{UnitClaim, line_in_txn};
use crate::job_workload::WorkloadStartAsk;
use crate::{EdgeActorClass, EntityId, Vault};

use super::ORDER_VERB;
use super::after::after_rule;
use super::blocker::Blocker;
use super::fit::scope_allowed;
use super::record::{
    AttemptEnd, CancelWhy, EndKind, GiveUpWhy, OrderAttempt, OrderCharge, OrderState, OrderedBy,
    SlotDecision, WORK_ORDERS, WorkOrder, attempt_job_id,
};
use super::setting_keys::retry_policy_in_txn;

/// The attempt a start makes for an order, as the built start carries it into its write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrderAttemptRef {
    pub order: EntityId,
    /// The order's revision when the loop read it.
    pub revision: u64,
    pub n: u16,
    pub machine: Option<EntityId>,
    pub ranked: SlotDecision,
    pub placed: SlotDecision,
}

/// Who the start acts for, as the order's authority stands in the start's own read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderStarter {
    /// The owner's recorded act: he showed the maximum when he ordered, at `ordered_at_ms`.
    Owner { owner: EntityId, ordered_at_ms: u64 },
    /// An agent under `grant`, the Grant it ordered under: it stands for `vault.jobs.order`
    /// and, for an offer's charge, is the Grant that starts the agent's GPU jobs, so the start
    /// checks the maximum the owner set beside it.
    Agent { actor: EntityId, grant: EntityId },
}

/// Why the start's write made no attempt for an order.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AttemptRefused {
    /// The order is no longer as the loop read it, or its wait ran out.
    #[error("the work order changed since the loop read it")]
    OrderChanged,
    #[error("the work order is blocked: {0}")]
    Blocked(Blocker),
}

impl AttemptRefused {
    /// The reason code a caller branches on.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::OrderChanged => "order_changed",
            Self::Blocked(blocker) => blocker.code(),
        }
    }
}

/// Whether the Grant `grant`, by its own id, stands for `actor` in `class` and `verb` now:
/// listed (not withdrawn), and the standing rule, asked for this Grant first, picks it.
/// Another live Grant of the same agent that names the verb never stands in for it.
fn grant_stands_for_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    grant: EntityId,
    verb: &str,
) -> crate::Result<bool> {
    let Some(listed) = agent_grants_for_store_in_txn(&vault.store, txn)?
        .into_iter()
        .find(|listed| listed.id == grant)
    else {
        return Ok(false);
    };
    let ours = listed.grant;
    let covers = |candidate: &FederationGrant| *candidate == ours;
    let standing =
        principal_standing_covering_or_lapse_in_txn(vault, txn, actor, class, verb, &covers)?;
    Ok(standing.is_ok_and(|standing| standing.grant == Some(grant)))
}

/// Whether `grant` stands for `actor` and `vault.gpu.jobs.start` now, asked for this Grant
/// first, as the issuer rechecks it before each send (`job_dispatch/recheck.rs`): a lower-id
/// Grant the owner gives the agent later never cancels an order made under `grant`. The start
/// reads the per-job maximum set beside `grant` itself.
fn grant_starts_jobs_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    actor: EntityId,
    class: EdgeActorClass,
    grant: EntityId,
) -> crate::Result<bool> {
    grant_stands_for_in_txn(vault, txn, actor, class, grant, GpuJobVerb::Start.name())
}

impl Vault {
    /// Whether the authority `order.ordered_by` names still lives in `txn` (I8: the order is
    /// carried out only while it does): the owner who ordered is not gone; or the exact Grant
    /// the agent ordered under still stands for it and `vault.jobs.order`, and, for an offer's
    /// charge, still stands for it and `vault.gpu.jobs.start` (the charge is "the caller's
    /// allowance (the built start)", 1.1). A line unit's order is made with
    /// `vault.arms.units.reserve` (row H3), so its Grant stands for that verb instead and still
    /// holds the line's lead role (the reviewer role for a review check), as the reserve judges
    /// the caller; the Grant's reach over the line's project was judged when the order was made.
    /// Each is asked for this Grant first: a revoked order Grant ends the order even while
    /// another Grant of the agent names the verb, and another live Grant that outranks it never
    /// does.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub(super) fn order_authority_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        order: &WorkOrder,
    ) -> crate::Result<Option<OrderStarter>> {
        match order.ordered_by {
            OrderedBy::Owner { owner: None } | OrderedBy::Agent { actor: None, .. } => Ok(None),
            OrderedBy::Owner { owner: Some(owner) } => {
                if crate::ports::owner_gone_in_txn(&self.store, txn, &owner)? {
                    return Ok(None);
                }
                Ok(Some(OrderStarter::Owner {
                    owner,
                    ordered_at_ms: order.ordered_at_ms,
                }))
            }
            OrderedBy::Agent {
                actor: Some(actor),
                class,
                grant,
            } => {
                if !matches!(class, EdgeActorClass::Agent | EdgeActorClass::System) {
                    return Ok(None);
                }
                if let OrderCharge::Line { line, purpose, .. } = &order.charge {
                    let stands = grant_stands_for_in_txn(
                        self,
                        txn,
                        actor,
                        class,
                        grant,
                        ARMS_UNITS_RESERVE_VERB,
                    )? && line_in_txn(self, txn, line)?
                        .is_some_and(|line| line.holds_role(&grant, role_for(*purpose)));
                    return Ok(stands.then_some(OrderStarter::Agent { actor, grant }));
                }
                if !grant_stands_for_in_txn(self, txn, actor, class, grant, ORDER_VERB)? {
                    return Ok(None);
                }
                if matches!(order.charge, OrderCharge::Offer { .. })
                    && !grant_starts_jobs_in_txn(self, txn, actor, class, grant)?
                {
                    return Ok(None);
                }
                Ok(Some(OrderStarter::Agent { actor, grant }))
            }
        }
    }

    /// The start's check of an order's attempt, read in `txn` (the built start's own read
    /// and its write, hunk H1): the order is as the loop read it and its wait has not run
    /// out, the attempt is its next one under the fixed job id `job`, the requester's
    /// authority lives, its `after` and caps let it run (row Q5), and the workload's approval
    /// covers the machine in a scope the order allows. Nothing is held when it says no.
    ///
    /// # Errors
    ///
    /// Storage errors. Every refusal is the inner `Err`.
    pub fn order_starter_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: &OrderAttemptRef,
        job: &EntityId,
        now_ms: u64,
    ) -> crate::Result<Result<OrderStarter, AttemptRefused>> {
        let Some(order) = WORK_ORDERS.get(&self.store, txn, &attempt.order)? else {
            return Ok(Err(AttemptRefused::OrderChanged));
        };
        let in_turn = order.revision == attempt.revision
            && matches!(order.state, OrderState::Open { .. })
            && order.cancel.is_none()
            && !order.wait_ran_out(now_ms)
            && attempt.n == order.next_attempt_number()
            && order.last_attempt().is_none_or(|last| last.end.is_some())
            && attempt_job_id(&order.id, attempt.n)? == *job;
        if !in_turn {
            return Ok(Err(AttemptRefused::OrderChanged));
        }
        let Some(starter) = self.order_authority_in_txn(txn, &order)? else {
            return Ok(Err(AttemptRefused::Blocked(Blocker::GrantNotLive)));
        };
        if let Some(blocker) = self.attempt_conditions_in_txn(txn, &order)? {
            return Ok(Err(AttemptRefused::Blocked(blocker)));
        }
        if let (Some(machine), Some(workload_starter)) =
            (attempt.machine, order.ordered_by.starter())
        {
            let ask = WorkloadStartAsk {
                workload: &order.workload,
                machine,
                maximum_secs: order.request.maximum_secs,
                starter: workload_starter,
            };
            match self.workload_approval_in_txn(txn, &ask, now_ms)? {
                Err(refused) => return Ok(Err(AttemptRefused::Blocked(Blocker::from(&refused)))),
                Ok(pin) if !scope_allowed(&order.limits, &pin.scope) => {
                    return Ok(Err(AttemptRefused::Blocked(Blocker::scope_not_allowed(
                        &pin.scope,
                    ))));
                }
                Ok(_) => {}
            }
        }
        Ok(Ok(starter))
    }

    /// [`Self::order_starter_in_txn`] in the start's write, then the order's attempt entry
    /// beside the job row the start writes: the order runs attempt `attempt.n` under `job`.
    /// One write, so a crash leaves one attempt or none, and a cancel that wrote first makes
    /// this refuse.
    ///
    /// # Errors
    ///
    /// Storage errors. Every refusal is the inner `Err`, and writes nothing.
    pub fn record_order_attempt_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        attempt: &OrderAttemptRef,
        job: &EntityId,
        now_ms: u64,
    ) -> crate::Result<Result<OrderStarter, AttemptRefused>> {
        let starter = match self.order_starter_in_txn(txn, attempt, job, now_ms)? {
            Ok(starter) => starter,
            Err(refused) => return Ok(Err(refused)),
        };
        let Some(mut order) = WORK_ORDERS.get(&self.store, txn, &attempt.order)? else {
            return Ok(Err(AttemptRefused::OrderChanged));
        };
        order.attempts.push(OrderAttempt {
            n: attempt.n,
            job: *job,
            machine: attempt.machine,
            ranked: attempt.ranked.clone(),
            placed: attempt.placed.clone(),
            made_at_ms: now_ms,
            started_at_ms: None,
            end: None,
        });
        order.state = OrderState::Running { attempt: attempt.n };
        order.retry_not_before_ms = None;
        if !self.put_work_order_in_txn(txn, &mut order, now_ms)? {
            return Ok(Err(AttemptRefused::OrderChanged));
        }
        Ok(Ok(starter))
    }

    /// The starter of the unit claim `claim` for the order attempt `attempt` (row H3), read in
    /// the claimed start's write: the claim is the one the attempt's reserve made (the order's
    /// claim key for attempt `n`, under the job id the order and `n` fix), reserved by the
    /// order's requester under the authority the order records. `None` for any other claim,
    /// which the start refuses and leaves as it is.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn order_claim_starter_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: &OrderAttemptRef,
        claim: &UnitClaim,
    ) -> crate::Result<Option<EntityId>> {
        let Some(order) = WORK_ORDERS.get(&self.store, txn, &attempt.order)? else {
            return Ok(None);
        };
        if order.claim_key(attempt.n) != Some(claim.key())
            || attempt_job_id(&order.id, attempt.n)? != claim.id
        {
            return Ok(None);
        }
        Ok(match order.ordered_by {
            OrderedBy::Owner { owner: Some(owner) } => {
                (claim.grant.is_none() && claim.reserved_by == Some(owner)).then_some(owner)
            }
            OrderedBy::Agent {
                actor: Some(actor),
                grant,
                ..
            } => (claim.grant == Some(grant) && claim.reserved_by == Some(actor)).then_some(actor),
            OrderedBy::Owner { owner: None } | OrderedBy::Agent { actor: None, .. } => None,
        })
    }

    /// Whether the order attempt `attempt` may still start the job `job` its reserve fixed,
    /// read in the claimed start's write (row H3): the attempt is the order's live one with no
    /// end, no cancel reached the order, and its requester's authority lives. The reserve's
    /// write moved the order to `Running` and bumped its revision, so the revision the loop
    /// read is not compared; a cancel or an end written since shows in the order itself.
    ///
    /// # Errors
    ///
    /// Storage errors. Every refusal is the inner `Err`.
    pub fn order_attempt_starts_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: &OrderAttemptRef,
        job: &EntityId,
    ) -> crate::Result<Result<(), AttemptRefused>> {
        let Some(order) = WORK_ORDERS.get(&self.store, txn, &attempt.order)? else {
            return Ok(Err(AttemptRefused::OrderChanged));
        };
        let live = matches!(order.state, OrderState::Running { attempt: n } if n == attempt.n)
            && order.cancel.is_none()
            && order
                .last_attempt()
                .is_some_and(|last| last.n == attempt.n && last.job == *job && last.end.is_none());
        if !live {
            return Ok(Err(AttemptRefused::OrderChanged));
        }
        if self.order_authority_in_txn(txn, &order)?.is_none() {
            return Ok(Err(AttemptRefused::Blocked(Blocker::GrantNotLive)));
        }
        Ok(Ok(()))
    }

    /// Whether the loop may stop `job` for the order `attempt` names, read in `txn` (the built
    /// cancel's own write, hunk H1): a cancel reached the order and `job` is its live attempt.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn order_stop_reaches_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        attempt: &OrderAttemptRef,
        job: &EntityId,
    ) -> crate::Result<bool> {
        Ok(WORK_ORDERS
            .get(&self.store, txn, &attempt.order)?
            .is_some_and(|order| {
                order.cancel.is_some()
                    && order
                        .last_attempt()
                        .is_some_and(|last| last.job == *job && last.end.is_none())
            }))
    }

    /// The owner wrote off `job`, an order's attempt whose end the machine cannot give (pass
    /// 33, door 10): the attempt ends `WrittenOff` and the order gives up, or is cancelled when
    /// a cancel reached it first. Nothing starts again unless somebody orders again. The
    /// write-off door calls this in its own write; a job no order made is left alone.
    ///
    /// # Errors
    ///
    /// Storage errors.
    pub fn order_attempt_written_off_in_txn(
        &self,
        txn: &mut heed::RwTxn<'_>,
        job: &EntityId,
        now_ms: u64,
    ) -> crate::Result<bool> {
        let found = WORK_ORDERS
            .scan(&self.store, txn)?
            .into_iter()
            .find(|(_, order)| {
                order
                    .last_attempt()
                    .is_some_and(|last| last.job == *job && last.end.is_none())
            });
        let Some((_, mut order)) = found else {
            return Ok(false);
        };
        let policy = retry_policy_in_txn(self, txn)?;
        let (_, decision) = after_rule(&order, EndKind::WrittenOff, &policy, now_ms);
        if let Some(last) = order.attempts.last_mut() {
            last.end = Some(AttemptEnd {
                kind: EndKind::WrittenOff,
                at_ms: now_ms,
                after: decision,
            });
        }
        order.state = match order.cancel {
            Some(cancel) => OrderState::Cancelled {
                why: CancelWhy::Asked { by: cancel.by },
            },
            None => OrderState::GivenUp {
                why: GiveUpWhy::WrittenOff,
            },
        };
        self.put_work_order_in_txn(txn, &mut order, now_ms)
    }
}
