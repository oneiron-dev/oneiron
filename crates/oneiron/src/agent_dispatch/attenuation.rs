//! Live-ceiling attenuation and deterministic attenuated-fork registration.

use rmpv::Value;

use crate::agent_def::{
    AgentCeiling, AgentDefinition, decode_agent_definition, encode_agent_definition,
};
use crate::attempt_queue::AttemptId;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::temporal::TimeRange;

use super::dispatch::AgentDispatcher;
use super::types::{
    AGENT_DISPATCH_COMPAT_DEPTH_CAP, ATTENUATED_FORK_ID_DOMAIN, AgentDispatchInput,
    AgentDispatchTarget, AttenuatedDispatchTarget, restrict_agent_ceiling,
};
use crate::error::ArtifactError;

impl AgentDispatcher<'_> {
    /// Clamps the requested child row to the parent's LIVE ceiling, minting a
    /// deterministic run-scoped fork when the request is wider.
    ///
    /// Both ceilings come from STORED rows. Comparing the two frozen payload
    /// snapshots would not be enforcement: the snapshot's `ceiling` is ignored
    /// uniformly (design D11) and the gate resolves authority live at every
    /// write, so only the DISPATCHED ROW's stored ceiling binds anything.
    ///
    /// # Errors
    ///
    /// [`ArtifactError::AgentDefinitionNotFound`](crate::error::ArtifactError::AgentDefinitionNotFound) / [`ArtifactError::AgentNotDispatchable`](crate::error::ArtifactError::AgentNotDispatchable) /
    /// [`ArtifactError::AgentDefinitionDisabled`](crate::error::ArtifactError::AgentDefinitionDisabled) when the parent's own target row does
    /// not resolve, and [`ArtifactError::InvalidAgentDispatchInput`](crate::error::ArtifactError::InvalidAgentDispatchInput) when the
    /// attenuated fork cannot be registered. Never falls back to the wider row.
    pub(super) fn attenuate_child_target(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        parent_attempt: AttemptId,
        requested_ref: EntityId,
        requested_definition: AgentDefinition,
        run_id: Option<&str>,
        now: u64,
    ) -> Result<(AttenuatedDispatchTarget, AgentDefinition)> {
        let unattenuated = |ceiling: AgentCeiling, definition: AgentDefinition| {
            (
                AttenuatedDispatchTarget {
                    target: AgentDispatchTarget::Custom(requested_ref),
                    requested_definition_ref: requested_ref,
                    dispatched_definition_ref: requested_ref,
                    parent_ceiling: ceiling,
                    effective_child_ceiling: definition.ceiling,
                    forked_for_attenuation: false,
                },
                definition,
            )
        };
        let Some(parent_input) = self.parent_dispatch_input_in_txn(wtxn, parent_attempt)? else {
            // No resolvable dispatch lineage means no grant to attenuate: the
            // requested row stands on its own live ceiling, which the gate
            // still clamps at every write.
            let ceiling = requested_definition.ceiling;
            return Ok(unattenuated(ceiling, requested_definition));
        };
        // The parent's ACTUAL target row, read live — its own attenuated fork
        // when it was itself clamped, which is what makes this hold recursively.
        let parent_ceiling = self.dispatchable_definition(&parent_input.target)?.ceiling;
        let effective_child_ceiling =
            restrict_agent_ceiling(requested_definition.ceiling, parent_ceiling);
        if effective_child_ceiling == requested_definition.ceiling {
            return Ok(unattenuated(parent_ceiling, requested_definition));
        }

        let source_fingerprint = source_content_fingerprint(&requested_definition)?;
        let fork_ref =
            attenuated_fork_id(requested_ref, &source_fingerprint, parent_attempt, run_id)?;
        // The fork is the row this dispatch NAMES, so its in-memory body is
        // also the composition snapshot: re-reading it would open a second
        // snapshot that cannot see this transaction's own write.
        let fork = self.register_attenuated_fork(
            wtxn,
            fork_ref,
            requested_ref,
            &requested_definition,
            &source_fingerprint,
            effective_child_ceiling,
            parent_attempt,
            run_id,
            now,
        )?;
        Ok((
            AttenuatedDispatchTarget {
                target: AgentDispatchTarget::Custom(fork_ref),
                requested_definition_ref: requested_ref,
                dispatched_definition_ref: fork_ref,
                parent_ceiling,
                effective_child_ceiling,
                forked_for_attenuation: true,
            },
            fork,
        ))
    }

    /// Writes (or idempotently reuses) the attenuated fork row through the
    /// ordinary AGENT_DEF entity door: copied composition, restricted ceiling,
    /// provenance naming the source row, the parent attempt, and the run.
    #[expect(
        clippy::too_many_arguments,
        reason = "the fork's provenance triple is the point; bundling it would hide it"
    )]
    fn register_attenuated_fork(
        &self,
        wtxn: &mut heed::RwTxn<'_>,
        fork_ref: EntityId,
        source_ref: EntityId,
        source: &AgentDefinition,
        source_fingerprint: &blake3::Hash,
        ceiling: AgentCeiling,
        parent_attempt: AttemptId,
        run_id: Option<&str>,
        now: u64,
    ) -> Result<AgentDefinition> {
        let mut fork = source.clone();
        fork.ceiling = ceiling;
        fork.forked_from = Some(source_ref);
        // `sys.*` logical ids are reserved to seeded rows: a fork is an ordinary
        // row and must not claim one.
        fork.logical_id = None;
        fork.provenance = Value::Map(vec![
            (
                Value::from("source_agent_def"),
                Value::from(source_ref.to_hex()),
            ),
            (
                Value::from("parent_attempt"),
                Value::from(crate::entity_id::bytes_to_hex_lower(
                    parent_attempt.as_bytes(),
                )),
            ),
            (
                Value::from("run_id"),
                run_id.map_or(Value::Nil, Value::from),
            ),
            (
                Value::from("source_fingerprint"),
                Value::from(source_fingerprint.to_hex().as_str()),
            ),
            (
                Value::from("attenuated_ceiling"),
                Value::from(ceiling.as_str()),
            ),
        ]);

        if let Some(raw) = self.vault.store.entities.get(wtxn, fork_ref.as_bytes())? {
            // Deterministic id: a retried spawn finds its own fork. Anything
            // else occupying the id is a typed failure, never a silent reuse of
            // a row with foreign composition (ceiling, provenance, body).
            let header = crate::batch::EntityMetadataHeader::parse(&raw).ok_or(Error::Artifact(
                ArtifactError::InvalidAgentDispatchInput("attenuated fork row header is malformed"),
            ))?;
            if header.entity_type != ENTITY_TYPE_AGENT_DEF {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "attenuated fork id is occupied by a foreign row",
                )));
            }
            let stored = decode_agent_definition(&raw[crate::batch::ENTITY_METADATA_HEADER_LEN..])
                .map_err(|_| {
                    Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                        "attenuated fork row does not decode",
                    ))
                })?;
            // Idempotent reuse requires the full expected composition — matching
            // ceiling + forked_from alone must not accept a foreign body.
            if stored != fork {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "attenuated fork id is occupied by a foreign row",
                )));
            }
            return Ok(stored);
        }

        let body = encode_agent_definition(&fork).map_err(|_| {
            Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                "attenuated fork does not encode as an AGENT_DEF body",
            ))
        })?;
        self.vault
            .batch_in()
            .put(
                &fork_ref,
                ENTITY_TYPE_AGENT_DEF,
                TimeRange {
                    start: now,
                    end: now,
                },
                now,
                &body,
            )
            .apply(wtxn)
            .map_err(|_| {
                Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "attenuated fork row could not be registered",
                ))
            })?;
        Ok(fork)
    }
}

/// The attenuated fork's row id: deterministic in `(source row, source
/// content fingerprint, parent attempt, run)`, so a retried spawn of the same
/// source revision finds its own fork, while a source row updated in place
/// mints a DISTINCT fork instead of colliding with the stale occupant.
pub(super) fn attenuated_fork_id(
    source_ref: EntityId,
    source_fingerprint: &blake3::Hash,
    parent_attempt: AttemptId,
    run_id: Option<&str>,
) -> Result<EntityId> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ATTENUATED_FORK_ID_DOMAIN);
    hasher.update(source_ref.as_bytes());
    hasher.update(source_fingerprint.as_bytes());
    hasher.update(parent_attempt.as_bytes());
    hasher.update(run_id.unwrap_or_default().as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    EntityId::from_bytes(bytes).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "attenuated fork id collided with a reserved id",
        ))
    })
}

/// The content fingerprint that joins fork identity: the canonical encoding
/// of the REQUESTED source definition, hashed. Recorded in fork provenance,
/// so the revision a fork was minted from is always auditable.
pub(super) fn source_content_fingerprint(source: &AgentDefinition) -> Result<blake3::Hash> {
    let encoded = encode_agent_definition(source).map_err(|_| {
        Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "source definition does not encode as an AGENT_DEF body",
        ))
    })?;
    Ok(blake3::hash(&encoded))
}

/// MALFORMED IS NOT ZERO: a parent whose depth cannot be read is a schema-v1
/// (or non-dispatch) lineage, and the CONFIGURED compatibility cap answers for
/// it — bounded, not unbounded, and not a refusal. Only a STORED `Some(0)` is
/// the exhausted lineage.
pub(super) fn child_depth_from(parent: Option<AgentDispatchInput>) -> Result<u8> {
    parent
        .and_then(|input| input.depth_remaining)
        .unwrap_or(AGENT_DISPATCH_COMPAT_DEPTH_CAP)
        .checked_sub(1)
        .ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
            "agent dispatch recursion depth is exhausted",
        )))
}
