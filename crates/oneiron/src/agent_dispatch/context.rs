//! Spawn-context resolution, sibling-lineage admission, ancestor projection fold.

use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::context_projection::{
    CONTEXT_PROJECTION_MAX_ANCESTORS, ContextResolutionRequest, ContextSpec,
    ResolvedContextProjection, resolve_context_spec, validate_spec_narrows,
};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};

use super::codec::record_dispatch_input;
use super::dispatch::AgentDispatcher;
use super::types::AgentDispatchTarget;
use crate::error::ArtifactError;

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
                        .and_then(|input| input.context_spec),
                    context_spec,
                ) {
                    validate_spec_narrows(&parent_spec, child_spec)?;
                }
                self.resolve_ancestor_projection(parent_attempt, world_scope)?
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
    fn require_sibling_result_lineage(
        &self,
        parent_attempt: Option<AttemptId>,
        run_id: Option<&str>,
        context_from: &[EntityId],
    ) -> Result<()> {
        if context_from.is_empty() {
            return Ok(());
        }
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
        let AgentDispatchTarget::Custom(parent_row) = parent_input.target;
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
    fn resolve_ancestor_projection(
        &self,
        attempt: AttemptId,
        _world_scope: crate::pipeline::WorldScope,
    ) -> Result<Option<ResolvedContextProjection>> {
        let queue = AttemptQueue::new(self.vault);
        let mut chain: Vec<(ContextSpec, crate::pipeline::WorldScope)> = Vec::new();
        let mut cursor = Some(attempt);
        while let Some(id) = cursor {
            if chain.len() >= CONTEXT_PROJECTION_MAX_ANCESTORS {
                break;
            }
            let Some(record) = queue.get(id)? else { break };
            let Some(input) = record_dispatch_input(&record) else {
                break;
            };
            chain.push((
                input.context_spec.unwrap_or_default(),
                input.definition.scope.to_world_scope(),
            ));
            cursor = decode_dreamer_attempt_payload(&record.payload)
                .ok()
                .and_then(|payload| payload.parent_attempt);
        }
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
                    world_scope: Some(*ancestor_scope),
                },
            )?);
        }
        Ok(projection)
    }
}
