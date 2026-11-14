//! `tasks.wait({agents, all?, n_of?, until?, step_key})` (slice 6.5b): a
//! run's wait over AGENT children it spawned with `self.agents.spawn`,
//! beside the reader-children wait the same row takes. The wait is the
//! caller's own attempt's: each child must be an attempt that attempt
//! spawned in its run, and every miss answers one refusal. A wait that is
//! done answers its reduction, kept under its step key. One that is not
//! parks an executor's run on it, and the write that ends a child, or the
//! due sweep once its `until` has passed ([AGENT-WAIT-DEADLINE]), delivers
//! the reduction as the run's reply. A caller with no executor step to park,
//! a host door's, is answered the reduction as it stands, and asks again
//! under the same key.

use std::collections::HashSet;

use super::HostSelfDispatcher;
use crate::agent_dispatch::{AgentWaitOpen, AgentWaitPolicy, agent_wait_attempt, open_agent_wait};
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::{
    AgentVerbAnswer, SelfDispatchOutcome, SelfDurableWait, SelfDurableWaitReason, SelfEffect,
    SelfFailedResult, TaskWaitSetCall, valid_reader_key,
};
use crate::error::{Error, Result};

/// The prompt of a run parked on a wait over AGENT children; the wait's id,
/// hex, follows it.
const AGENT_WAIT_SET_PROMPT: &str = "agent_wait_set:";
/// The most children one wait names.
const AGENT_WAIT_MAX_CHILDREN: usize = 256;

impl HostSelfDispatcher<'_> {
    /// The wait of this run's own attempt over the AGENT children `agents`
    /// names. `park` says the caller is an executor's step, which a wait
    /// that is not done parks; any other caller is answered the reduction as
    /// it stands. A call that names reader children or a request beside the
    /// agents, a bad id, policy or step key, a run bound to a room or to no
    /// agent attempt, or an attempt that is not this run's own child fails,
    /// and nothing waits.
    pub(super) fn dispatch_agent_wait(
        &self,
        call: &TaskWaitSetCall,
        agents: &[String],
        park: bool,
    ) -> Result<SelfDispatchOutcome> {
        let failed = |code: &str| {
            SelfDispatchOutcome::Failed(SelfFailedResult {
                effect: SelfEffect::TasksWaitSet,
                error: code.to_owned(),
                code: None,
                disk_floor: None,
            })
        };
        if !call.tasks.is_empty() || call.request.is_some() {
            return Ok(failed("task_wait_invalid"));
        }
        let mut seen = HashSet::with_capacity(agents.len());
        let mut children = Vec::with_capacity(agents.len());
        for agent in agents {
            match agent_wait_attempt(agent) {
                Some(child) if seen.insert(child) => children.push(child),
                _ => return Ok(failed("task_wait_invalid")),
            }
        }
        let policy = match (call.all, call.n_of) {
            (None | Some(true), None) => AgentWaitPolicy::All,
            (None | Some(false), Some(n)) if n >= 1 && n as usize <= children.len() => {
                AgentWaitPolicy::NOf { n }
            }
            _ => return Ok(failed("task_wait_invalid")),
        };
        if children.is_empty()
            || children.len() > AGENT_WAIT_MAX_CHILDREN
            || !valid_reader_key(&call.step_key)
        {
            return Ok(failed("task_wait_invalid"));
        }
        // The wait is the caller's own attempt's, in the canonical vault: a
        // run bound to a room, or to no agent attempt, waits on none.
        let (ExecutorStorage::Canonical(vault), Some(parent)) = (&self.storage, self.agent_parent)
        else {
            return Ok(failed("task_wait_unbound"));
        };
        Ok(
            match open_agent_wait(
                vault,
                self.actor,
                parent,
                &children,
                policy,
                &call.step_key,
                call.until,
            )? {
                AgentWaitOpen::Reduced { wait, result } if park && !result.done => {
                    SelfDispatchOutcome::DurableWait(SelfDurableWait {
                        wait_id: wait,
                        effect: SelfEffect::TasksWait,
                        reason: SelfDurableWaitReason::PeerResult,
                        prompt: Some(format!("{AGENT_WAIT_SET_PROMPT}{}", wait.to_hex())),
                    })
                }
                AgentWaitOpen::Reduced { result, .. } => {
                    let output = serde_json::to_value(&result)
                        .map_err(|_| Error::InvariantViolation("agent wait answer encode"))?;
                    // The answer names attempts, their states and result
                    // refs, and serves no vault row.
                    SelfDispatchOutcome::AgentVerb(AgentVerbAnswer::new(output, Some(Vec::new())))
                }
                AgentWaitOpen::Changed => failed("task_wait_changed"),
                // Two tries of one child are one child, as a repeated id is.
                AgentWaitOpen::SameChild => failed("task_wait_invalid"),
                AgentWaitOpen::NotOwn => failed("task_wait_not_own"),
            },
        )
    }
}
