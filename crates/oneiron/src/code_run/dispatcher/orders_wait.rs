//! `vault.jobs.orders.wait` (pass 34 row Q1, 14.2): the run waits on one
//! work order its actor may read, until the order's first started attempt
//! or its end. The read checks the verb's Grant and the order's reach in the
//! work order door's own transaction, as `vault.jobs.orders.get` does: a run
//! that cannot read the order never parks. While the order has not reached
//! the milestone, a run at an executor call site parks on the order's wait,
//! which the order's own writer settles with the view; no model turn runs
//! in between. A call with no call site cannot park and is answered at once,
//! as the host door answers.

use super::{ExecutorCallSite, HostSelfDispatcher};
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::types::{
    AGENT_VERB_SESSION_BOUND, AgentVerbAnswer, SelfDeniedResult, SelfDispatchOutcome, SelfEffect,
    SelfFailedResult,
};
use crate::code_run::{SelfDurableWait, SelfDurableWaitReason};
use crate::error::{Error, Result};
use crate::memory::{MEMORY_CODE_FORBIDDEN, MemoryError};
use crate::work_order::{WorkOrderWaitRequest, order_wait_id, work_order_wait_as};

/// The prompt of a parked order wait: the order's id and the milestone follow.
const ORDER_WAIT_PROMPT: &str = "work_order_wait:";

impl HostSelfDispatcher<'_> {
    /// The run's wait on `call.order`: the view at once when the order has
    /// reached `call.until`, else a park on its wait. A run bound to a
    /// session is refused: orders live in the canonical vault.
    pub(super) fn dispatch_jobs_orders_wait(
        &self,
        call: WorkOrderWaitRequest,
        site: Option<ExecutorCallSite<'_>>,
    ) -> Result<SelfDispatchOutcome> {
        let ExecutorStorage::Canonical(vault) = &self.storage else {
            return Ok(denied(AGENT_VERB_SESSION_BOUND));
        };
        let memory = vault.memory(self.actor.entity_ref(), self.actor.actor_class());
        let answer = match work_order_wait_as(&memory, self.owner_proof, &call) {
            Ok(answer) => answer,
            Err(error) => return Ok(refused(&error)),
        };
        if !answer.reached && site.is_some() {
            return Ok(SelfDispatchOutcome::DurableWait(SelfDurableWait {
                wait_id: order_wait_id(&call.order, call.until)?,
                effect: SelfEffect::JobsOrdersWait,
                reason: SelfDurableWaitReason::PeerResult,
                prompt: Some(format!(
                    "{ORDER_WAIT_PROMPT}{}:{}",
                    call.order.to_hex(),
                    call.until.name()
                )),
            }));
        }
        let output = serde_json::to_value(&answer)
            .map_err(|_| Error::InvariantViolation("work order wait answer encode"))?;
        // The answer names the order, its attempts, their decisions and the
        // node's receipt, and serves no vault row.
        Ok(SelfDispatchOutcome::AgentVerb(AgentVerbAnswer::new(
            output,
            Some(Vec::new()),
        )))
    }
}

/// A caller the verb does not admit is denied; any other door error (an
/// order it may not read answers `not_found`) is a failure the script reads.
fn refused(error: &MemoryError) -> SelfDispatchOutcome {
    if error.code == MEMORY_CODE_FORBIDDEN {
        return denied(&error.code);
    }
    SelfDispatchOutcome::Failed(SelfFailedResult {
        effect: SelfEffect::JobsOrdersWait,
        error: error.code.clone(),
        code: None,
        disk_floor: None,
    })
}

fn denied(code: &str) -> SelfDispatchOutcome {
    SelfDispatchOutcome::Denied(SelfDeniedResult {
        hook_notice: None,
        effect: SelfEffect::JobsOrdersWait,
        outcome: code.to_owned(),
        reason_codes: Vec::new(),
    })
}
