//! A parentless, run-bearing research root through ordinary dispatch
//! (`vault.research.create_root`, CAMPAIGN-ROOT). The caller's admission is
//! decided in the dispatch writer itself, before the root is read for or
//! written, and a repeat of a pending intent keeps the run its first call
//! minted, so the queue's dedupe returns that root rather than refusing a
//! second run on the same key.

use crate::attempt_queue::AttemptQueue;
use crate::context_projection::{ContextSpec, normalize_context_spec};
use crate::dreamer_runner::DREAMER_RUNNER_ATTEMPT_KIND;
use crate::entity_id::EntityId;
use crate::error::{ArtifactError, Error, Result};
use crate::memory::MemoryResult;

use super::types::{
    AGENT_DISPATCH_ATTEMPT_TYPE, AgentDispatchOutcome, AgentDispatchTarget, AgentSpawnContext,
    DispatchAgent,
};
use super::{AgentDispatcher, QueuedRequester};

/// The namespace of a research root's minted run id; the rest is a fresh
/// entity id from the vault's own source.
const RESEARCH_RUN_PREFIX: &str = "research:";

/// One research root to enqueue, its caller authenticated by the door.
pub(crate) struct ResearchRootRequest {
    /// The dispatchable AGENT_DEF the root attempt runs.
    pub(crate) agent: EntityId,
    /// The caller-scoped dedupe key: a repeat while that root is pending
    /// returns it with its run.
    pub(crate) dedupe_key: String,
    /// The root's brief, carried as its context briefing.
    pub(crate) briefing: String,
    /// The requester the caller's authenticated handle queues work under.
    pub(crate) requester: Option<QueuedRequester>,
    /// The vault's clock, unix seconds.
    pub(crate) now: u64,
}

impl AgentDispatcher<'_> {
    /// Enqueues one parentless root attempt for `request.agent` with a run of
    /// its own, through the ordinary dispatch writer: the vault ROOT project,
    /// the default context with the brief, no spend scope, room, team or
    /// plan, and the ordinary budget and launch admission.
    ///
    /// `admit` decides the caller in this writer's snapshot before anything
    /// else; its refusal writes nothing. A pending root on the same key is
    /// returned as ordinary dispatch returns a pending dedupe hit, before any
    /// live re-admission of its agent; a different agent or brief on that
    /// key is refused, never reused.
    ///
    /// # Errors
    ///
    /// `admit`'s refusal; every refusal of [`Self::dispatch_with_context`]
    /// for a root; a pending row on the key that carries no run; storage
    /// errors.
    pub(crate) fn dispatch_research_root(
        &self,
        request: ResearchRootRequest,
        admit: impl Fn(&heed::RoTxn<'_>) -> MemoryResult<()>,
    ) -> MemoryResult<AgentDispatchOutcome> {
        let target = AgentDispatchTarget::Custom(request.agent);
        let spawn = AgentSpawnContext {
            context_spec: Some(normalize_context_spec(
                ContextSpec::default().with_briefing(request.briefing),
            )),
            requester: request.requester,
            ..AgentSpawnContext::default()
        };
        let mut wtxn = self.vault.store.env.write_txn().map_err(Error::from)?;
        admit(&wtxn)?;
        let run_id = match self.pending_research_root_run_in_txn(&wtxn, &request.dedupe_key)? {
            Some(run_id) => run_id,
            None => {
                // A new root: the preflight of ordinary dispatch, in its
                // order, read in this writer.
                let run_id = format!(
                    "{RESEARCH_RUN_PREFIX}{}",
                    self.vault.new_entity_id()?.to_hex()
                );
                self.project_depth_limit_in_txn(&wtxn, None, None)?;
                let definition = self.dispatchable_definition_in_txn(&wtxn, &target)?;
                self.resolve_dispatch_context_in_txn(
                    &wtxn,
                    None,
                    spawn.context_spec.as_ref(),
                    &spawn.context_from,
                    Some(&run_id),
                    definition.scope.to_world_scope(),
                )?;
                run_id
            }
        };
        let outcome = self.dispatch_in_txn(
            &mut wtxn,
            None,
            DispatchAgent {
                target,
                parent_attempt: None,
                dedupe_key: Some(request.dedupe_key),
                run_id: Some(run_id),
                now: request.now,
            },
            spawn,
        )?;
        wtxn.commit().map_err(Error::from)?;
        self.vault.store.notify_attempt_observers();
        Ok(outcome)
    }

    /// The run of the root pending on `dedupe_key`, if one is pending.
    fn pending_research_root_run_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        dedupe_key: &str,
    ) -> Result<Option<String>> {
        let key = format!("{AGENT_DISPATCH_ATTEMPT_TYPE}:{dedupe_key}");
        AttemptQueue::new(self.vault)
            .pending_dedupe_in_txn(txn, DREAMER_RUNNER_ATTEMPT_KIND, &key)?
            .map(|pending| {
                pending
                    .run_id
                    .ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "the pending research root on this intent carries no run",
                    )))
            })
            .transpose()
    }
}
