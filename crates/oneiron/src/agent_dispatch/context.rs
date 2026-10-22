//! Spawn-context resolution, sibling-lineage admission, ancestor projection fold.

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::context_projection::{
    ContextResolutionRequest, ContextSpec, ResolvedContextProjection, resolve_context_spec,
    validate_spec_narrows,
};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::scan_check::{EngineScan, ScanCount};

use super::codec::record_dispatch_input;
use super::dispatch::AgentDispatcher;
use crate::error::ArtifactError;

/// One ancestor walk's dispatch levels (spec and scope, nearest first), the
/// first wrapper's member and every wrapper's binder.
type AncestorChain = (
    Vec<(ContextSpec, crate::pipeline::WorldScope)>,
    Option<EntityId>,
    Vec<crate::write_envelope::WriteActor>,
);

impl AgentDispatcher<'_> {
    /// Resolves the requested descriptor against LIVE state, folding the
    /// ancestor chain root-down so a `Default` projection inherits what its
    /// parent actually saw rather than the widest default.
    pub(super) fn resolve_dispatch_context(
        &self,
        parent_attempt: Option<AttemptId>,
        context_spec: Option<&ContextSpec>,
        context_from: &[EntityId],
        run_id: Option<&str>,
        world_scope: crate::pipeline::WorldScope,
    ) -> Result<ResolvedContextProjection> {
        let parent = match parent_attempt {
            None => None,
            Some(parent_attempt) => {
                // DECLARED bound: the child's requested scope against the
                // parent's stored scope, checked before either is resolved.
                if let (Some(parent_spec), Some(child_spec)) = (
                    self.parent_dispatch_input(parent_attempt)?
                        .map(|input| self.effective_context_spec(parent_attempt, &input))
                        .transpose()?,
                    context_spec,
                ) {
                    validate_spec_narrows(&parent_spec, child_spec)?;
                }
                self.resolve_ancestor_projection(parent_attempt)?
            }
        };
        let projection = resolve_context_spec(
            self.vault,
            ContextResolutionRequest {
                spec: context_spec.cloned().unwrap_or_default(),
                parent,
                context_from: context_from.to_vec(),
                world_scope: Some(world_scope),
            },
        )?;
        self.require_sibling_result_lineage(parent_attempt, run_id, context_from)?;
        Ok(projection)
    }

    /// `contextFrom` admission, stage two — SAME-PARENT/RUN LINEAGE, proved
    /// from attempt-tree data at the dispatch site (stage one, settlement and
    /// the result_ref binding, already failed closed inside
    /// `resolve_context_spec`). Each named TASK must have been created by the
    /// parent attempt's DISPATCHED agent row (its recorded create-owner), and
    /// the spawn must ride the parent attempt's exact run. A root spawn has no
    /// siblings to name; a foreign parent or run rejects with the same typed
    /// error — never a silent skip.
    pub(super) fn require_sibling_result_lineage(
        &self,
        parent_attempt: Option<AttemptId>,
        run_id: Option<&str>,
        context_from: &[EntityId],
    ) -> Result<()> {
        if context_from.is_empty() {
            return Ok(());
        }
        let parent_attempt = self.workflow_authority_parent(parent_attempt)?;
        let Some(parent_attempt) = parent_attempt else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "contextFrom names sibling results but there is no parent attempt",
            )));
        };
        let Some(parent_record) = AttemptQueue::new(self.vault).get(parent_attempt)? else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "contextFrom requires a parent attempt row",
            )));
        };
        if parent_record.run_id.as_deref() != run_id {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "contextFrom is admitted only inside the parent attempt's run",
            )));
        }
        let Some(parent_input) = record_dispatch_input(&parent_record) else {
            return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "contextFrom requires a parent with agent dispatch lineage",
            )));
        };
        let parent_row = parent_input.target.agent_definition_ref()?;
        for entity_ref in context_from {
            if crate::task_verb::task_create_owner(self.vault, *entity_ref)? != Some(parent_row) {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "contextFrom names a settled result from a different parent",
                )));
            }
        }
        Ok(())
    }

    /// Rebuilds what `attempt` projects, by folding its ancestors root-down.
    /// `None` when no ancestor carries a descriptor at all.
    ///
    /// The fold is what makes `MemoryProjection::Default` honest: resolving an
    /// ancestor's spec standalone would hand it the widest default, so a
    /// `Default` under an excluding grandparent would silently WIDEN.
    ///
    /// Under a member's bound run (FIX 5416) the projection is read on that
    /// member's own lane, the rows it does not read left out and counted.
    /// Under an owner's or agent's, each row meets the private threads it
    /// sits in under that binder's own cut (FIX 6412), and under an agent's
    /// or the system's, that binder's own admission too (FIX 6715). Each
    /// comes from the wrapper the fold crosses, which still adds no level;
    /// every level resolves as it does for any run.
    pub(super) fn resolve_ancestor_projection(
        &self,
        attempt: AttemptId,
    ) -> Result<Option<ResolvedContextProjection>> {
        // Every ancestor is read, however many (rule 5): past its threshold
        // row the walk asks whether everything is okay, counted on every way
        // out. No read transaction is held here; like each ancestor read
        // below, the threshold read opens its own.
        let mut walk = ScanCount::start_at(
            EngineScan::DispatchAncestorRows,
            attempt.as_bytes(),
            self.vault
                .scan_threshold(EngineScan::DispatchAncestorRows)?,
        );
        let mut seen = std::collections::HashSet::new();
        let walked = self.ancestor_chain(attempt, &mut seen);
        walk.rows(seen.len());
        walk.finish(self.vault);
        let Some((chain, member, binders)) = walked? else {
            return Ok(None);
        };
        if chain.is_empty() {
            return Ok(None);
        }

        let mut projection = None;
        // Root-down: each level narrows the one above it.
        for (index, (spec, ancestor_scope)) in chain.iter().rev().enumerate() {
            if index > 0 {
                validate_spec_narrows(&chain[chain.len() - index].0, spec)?;
            }
            projection = Some(resolve_context_spec(
                self.vault,
                ContextResolutionRequest {
                    spec: spec.clone(),
                    parent: projection,
                    context_from: Vec::new(),
                    world_scope: Some(ancestor_scope.clone()),
                },
            )?);
        }
        let projection = match (projection, member) {
            (Some(projection), Some(member)) => Some(self.member_context(projection, member)?),
            (projection, _) => projection,
        };
        projection
            .map(|projection| self.binder_context(projection, &binders))
            .transpose()
    }

    /// The walk [`Self::resolve_ancestor_projection`] counts, each attempt it
    /// reads in `seen`: every dispatch level's spec and scope, the first
    /// wrapper's member and every wrapper's binder. `None` when `attempt`
    /// itself is no dispatch lineage.
    fn ancestor_chain(
        &self,
        attempt: AttemptId,
        seen: &mut std::collections::HashSet<AttemptId>,
    ) -> Result<Option<AncestorChain>> {
        let queue = AttemptQueue::new(self.vault);
        let mut chain: Vec<(ContextSpec, crate::pipeline::WorldScope)> = Vec::new();
        let mut member = None;
        let mut binders = Vec::new();
        let mut cursor = Some(attempt);
        while let Some(id) = cursor {
            if !seen.insert(id) {
                return Err(super::widen_record::invalid("context ancestor cycle"));
            }
            let Some(record) = queue.get(id)? else {
                if chain.is_empty() {
                    return Ok(None);
                }
                return Err(super::widen_record::invalid("context ancestor is missing"));
            };
            if super::workflow_record::is_wrapper(&record) {
                if member.is_none() {
                    member = self.workflow_member(&record)?;
                }
                binders.extend(self.workflow_binder(&record)?);
                cursor = self.workflow_authority_parent(Some(id))?;
                continue;
            }
            let Some(input) = record_dispatch_input(&record) else {
                if chain.is_empty() {
                    return Ok(None);
                }
                return Err(super::widen_record::invalid(
                    "context ancestor is not dispatch lineage",
                ));
            };
            chain.push((
                self.effective_context_spec(id, &input)?,
                self.dispatchable_definition(&input.target)?
                    .scope
                    .to_world_scope(),
            ));
            cursor = decode_dreamer_attempt_payload(&record.payload)?.parent_attempt;
        }
        Ok(Some((chain, member, binders)))
    }
}
