//! The grant powers a running agent acts under (SPAWN-KNOB, ARCH-0053:20):
//! which instance's grant decides its spawns and its authored definitions,
//! and the receipted refusal when the power is off. The writers that launch
//! a child or mint a definition check the same grant again in their own
//! transaction; this is where the refusal is answered and receipted.

use super::HostSelfDispatcher;
use crate::agent_def::{
    AgentPowerTarget, AgentPowers, ChildPowerRequest, SAVE_AGENT_OFF, SPAWN_OFF, child_agent_powers,
};
use crate::code_run::storage::ExecutorStorage;
use crate::code_run::{SelfDeniedResult, SelfEffect};
use crate::edge::EdgeActorClass;
use crate::error::Result;

impl HostSelfDispatcher<'_> {
    /// What the agent this dispatcher runs as holds now, and whose grant
    /// decided: the reader child's own when it runs one that was born with
    /// a grant, else its attempt's, else its agent's root grant. The
    /// instances are the host's bindings, never guest fields.
    fn caller_agent_powers(&self) -> Result<(AgentPowers, AgentPowerTarget)> {
        let mut instances = Vec::with_capacity(2);
        if let Some(child) = &self.reader_child {
            instances.push(AgentPowerTarget::ReaderTask(child.task));
        }
        if let Some(attempt) = self.agent_parent {
            instances.push(AgentPowerTarget::Attempt(attempt));
        }
        self.storage
            .effective_agent_powers(self.actor.entity_ref(), &instances)
    }

    /// Whether this dispatcher runs as an agent: only an agent holds powers.
    fn runs_as_agent(&self) -> bool {
        self.actor.actor_class() == EdgeActorClass::Agent
    }

    /// The deny answer for `effect`, its Gate receipt committed first on the
    /// vault's own route. An off-record session's refusal stays on its own
    /// record: its bridge row answers it, and nothing reaches the vault's.
    fn refuse_agent_power(
        &self,
        effect: SelfEffect,
        target: AgentPowerTarget,
        reason: &'static str,
        request: &[u8],
    ) -> Result<SelfDeniedResult> {
        if let ExecutorStorage::Canonical(vault) = &self.storage {
            let mut wtxn = vault.store.env.write_txn()?;
            crate::gate::record_agent_power_refusal_in_txn(
                vault, &mut wtxn, self.actor, target, effect, request, reason,
            )?;
            wtxn.commit()?;
        }
        Ok(SelfDeniedResult {
            effect,
            outcome: "deny".to_owned(),
            reason_codes: vec![reason.to_owned()],
            hook_notice: None,
        })
    }

    /// Checks a spawn (`effect`) the caller asks with `requested` for its
    /// child: refused when the caller's `spawn` is off, or when it asks a
    /// power it does not hold itself. Allowed, the grant a child of the
    /// caller's own agent is born with (a reader child); `None` for a caller
    /// that is no agent.
    pub(super) fn check_spawn_powers(
        &self,
        effect: SelfEffect,
        requested: Option<ChildPowerRequest>,
        request: &[u8],
    ) -> Result<std::result::Result<Option<AgentPowers>, SelfDeniedResult>> {
        if !self.runs_as_agent() {
            return Ok(Ok(None));
        }
        let (held, target) = self.caller_agent_powers()?;
        if !held.spawn {
            return self
                .refuse_agent_power(effect, target, SPAWN_OFF, request)
                .map(Err);
        }
        let (root, _) = self
            .storage
            .effective_agent_powers(self.actor.entity_ref(), &[])?;
        match child_agent_powers(held, root, requested.unwrap_or_default()) {
            Ok(child) => Ok(Ok(Some(child))),
            Err(reason) => self
                .refuse_agent_power(effect, target, reason, request)
                .map(Err),
        }
    }

    /// Checks an authored definition (`vault.agents.put`) against the
    /// caller's `save_agent`; `Some` is the receipted refusal.
    pub(super) fn check_save_agent_power(
        &self,
        request: &[u8],
    ) -> Result<Option<SelfDeniedResult>> {
        if !self.runs_as_agent() {
            return Ok(None);
        }
        let (held, target) = self.caller_agent_powers()?;
        if held.save_agent {
            return Ok(None);
        }
        self.refuse_agent_power(SelfEffect::AgentsPut, target, SAVE_AGENT_OFF, request)
            .map(Some)
    }

    /// The attempt this dispatcher's own authored definitions answer to, for
    /// the author writer's own `save_agent` check.
    pub(super) fn power_instance(&self) -> Option<AgentPowerTarget> {
        self.agent_parent.map(AgentPowerTarget::Attempt)
    }
}
