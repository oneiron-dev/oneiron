//! Live-ceiling attenuation and deterministic attenuated-fork registration.

use crate::ports::EntityStoreRead;
use rmpv::Value;

use crate::agent_def::{
    AgentCeiling, AgentDefinition, bind_delegation_parent_in_txn, decode_agent_definition,
    delegation_parent_in_txn, encode_agent_definition,
};
use crate::attempt_queue::{AttemptId, AttemptQueue};
use crate::dreamer_runner::decode_dreamer_attempt_payload;
use crate::edge::EdgeActorClass;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::gate::PolicyApprovalCeiling;
use crate::registry::ENTITY_TYPE_AGENT_DEF;
use crate::scan_check::{EngineScan, ScanCount};
use crate::store::Store;
use crate::temporal::TimeRange;

use super::codec::record_dispatch_input;
use super::dispatch::AgentDispatcher;
use super::types::{
    ATTENUATED_FORK_ID_DOMAIN, AgentDispatchInput, AgentDispatchTarget, AttenuatedDispatchTarget,
    restrict_agent_ceiling,
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
        // when it was itself clamped — met with the bound the gate reads off
        // it at every write and off every agent above it (FIX 9559).
        let parent_row = self.dispatchable_definition_in_txn(wtxn, &parent_input.target)?;
        let parent_ceiling = self.live_parent_ceiling_in_txn(
            wtxn,
            parent_attempt,
            parent_input.target.agent_definition_ref()?,
            parent_row.ceiling,
        )?;
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

        if let Some(raw) = self.vault.store.port_entity_record(wtxn, &fork_ref)? {
            // Deterministic id: a retried spawn finds its own fork. Anything
            // else occupying the id is a typed failure, never a silent reuse of
            // a row with foreign composition (ceiling, provenance, body).

            if raw.entity_type != ENTITY_TYPE_AGENT_DEF {
                return Err(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "attenuated fork id is occupied by a foreign row",
                )));
            }
            let stored = decode_agent_definition(&raw.body).map_err(|_| {
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
            bind_delegation_parent_in_txn(&self.vault.store, wtxn, &fork_ref, parent_attempt)?;
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
        // The delegation the fork was minted under is the id's for good: its
        // pin keeps it across every later put, delete and restore.
        bind_delegation_parent_in_txn(&self.vault.store, wtxn, &fork_ref, parent_attempt)?;
        Ok(fork)
    }

    /// The ceiling `parent_attempt`'s children answer to, read live (FIX
    /// 9559): its target row's stored ceiling, met with the bound the gate
    /// reads off that row at every write and with the same bound of every
    /// agent above it on its delegation chain. Every ancestor is read,
    /// however many (rule 5): past its row the walk asks whether everything
    /// is okay, counted on every way out.
    fn live_parent_ceiling_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        parent_attempt: AttemptId,
        parent_target: EntityId,
        parent_row_ceiling: AgentCeiling,
    ) -> Result<AgentCeiling> {
        let store = &self.vault.store;
        let scope = [parent_attempt.as_bytes().as_slice(), b"delegation"].concat();
        let mut walk = ScanCount::start(store, txn, EngineScan::DispatchAncestorRows, &scope)?;
        let mut seen = std::collections::HashSet::new();
        let ceiling = self.delegation_chain_ceiling(
            txn,
            parent_attempt,
            parent_target,
            parent_row_ceiling,
            &mut seen,
        );
        walk.rows(seen.len());
        walk.defer(store);
        ceiling
    }

    /// The walk [`Self::live_parent_ceiling_in_txn`] counts, each attempt it
    /// reads in `seen`. The chain follows each target's pinned delegation
    /// parent, else its attempt's recorded parent (a workflow wrapper
    /// crossed), and ends at the first attempt that is no agent dispatch or
    /// does not read. A chain that comes back on itself proves no grant and
    /// holds at `Proposed`.
    fn delegation_chain_ceiling(
        &self,
        txn: &heed::RoTxn<'_>,
        parent_attempt: AttemptId,
        parent_target: EntityId,
        parent_row_ceiling: AgentCeiling,
        seen: &mut std::collections::HashSet<AttemptId>,
    ) -> Result<AgentCeiling> {
        let store = &self.vault.store;
        let queue = AttemptQueue::new(self.vault);
        let mut ceiling = restrict_agent_ceiling(
            parent_row_ceiling,
            live_row_ceiling(store, txn, parent_target),
        );
        let mut attempt = parent_attempt;
        let mut target = parent_target;
        seen.insert(attempt);
        loop {
            let next = match delegation_parent_in_txn(store, txn, &target)? {
                Some(parent) => Some(parent),
                None => {
                    let recorded = queue.get_in_txn(txn, attempt)?.and_then(|row| {
                        decode_dreamer_attempt_payload(&row.payload)
                            .ok()
                            .and_then(|payload| payload.parent_attempt)
                    });
                    self.workflow_authority_parent_in_txn(txn, recorded)
                        .ok()
                        .flatten()
                }
            };
            let Some(next) = next else {
                break;
            };
            if !seen.insert(next) {
                return Ok(AgentCeiling::Proposed);
            }
            let Some(next_target) = queue
                .get_in_txn(txn, next)?
                .as_ref()
                .and_then(record_dispatch_input)
                .and_then(|input| input.target.agent_definition_ref().ok())
            else {
                break;
            };
            ceiling = restrict_agent_ceiling(ceiling, live_row_ceiling(store, txn, next_target));
            attempt = next;
            target = next_target;
        }
        Ok(ceiling)
    }
}

/// The bound the gate reads off agent row `id` at every write
/// ([`crate::gate::agent_definition_ceiling_for_actor`]): its stored ceiling
/// met with its fork parent row's, its lifecycle and its foreign chain. A row
/// that bears no definition bound adds none here.
fn live_row_ceiling(store: &Store, txn: &heed::RoTxn<'_>, id: EntityId) -> AgentCeiling {
    match crate::gate::agent_definition_ceiling_for_actor(
        store,
        txn,
        crate::WriteActor::new(id, EdgeActorClass::Agent),
    ) {
        Some(PolicyApprovalCeiling::Proposed) => AgentCeiling::Proposed,
        Some(PolicyApprovalCeiling::Auto) | None => AgentCeiling::Auto,
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

/// The depth a child of `parent` persists: one less than the parent's
/// explicit slice, refused only once that slice is spent. A parent with no
/// explicit slice (a lineage under no owner-set depth, or an attempt that is
/// no agent dispatch) bounds nothing (FIX 9560): `None`.
pub(super) fn child_depth_from(parent: Option<AgentDispatchInput>) -> Result<Option<u64>> {
    parent
        .and_then(|input| input.depth_remaining)
        .map(|depth| {
            depth
                .checked_sub(1)
                .ok_or(Error::Artifact(ArtifactError::InvalidAgentDispatchInput(
                    "agent dispatch recursion depth is exhausted",
                )))
        })
        .transpose()
}
