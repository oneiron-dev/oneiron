//! Exact-operation envelope handoff. This is not a gate authorization.

use std::collections::VecDeque;

use super::{
    ApplyOpsGateMode, BaseWriteOrigin, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader,
    reject_overlay_member_base_write,
};
use crate::claim::{
    ClaimApprovalStatus, ClaimBody, ClaimLifecycleStatus, ClaimSource, decode_claim_body,
    encode_claim_body,
};
use crate::error::{Error, Result};
use crate::side_table::{self, Raw, SideTable};
use crate::store::Store;
use crate::write_envelope::{SourceLineage, WriteActor, WriteEnvelope, WriteProvenance};
use crate::{EntityId, Vault};
use rmpv::Value;

/// Private local binding digest proving which writer authored/finalized a
/// CLAIM row. Key: id16.
const AUTHORED: SideTable<EntityId, [u8; 32], Raw> =
    SideTable::new(&side_table::CLAIM_MATERIALIZATION_AUTHORED);

/// Private fields prevent a caller from attaching an arbitrary envelope to a Put.
/// The provenance owner supplies its sealed payload. Lifecycle reconstruction
/// instead requires a current row and a host-authored immutable binding.
#[derive(Debug)]
pub(crate) struct ClaimMaterialization {
    id: EntityId,
    occurred: crate::temporal::TimeRange,
    learned_at: u64,
    data: Vec<u8>,
    reserved: bool,
    envelope: WriteEnvelope,
    prior: Option<[u8; 32]>,
    approval: bool,
}

impl ClaimMaterialization {
    pub(crate) fn provenance(write: crate::provenance::ProvenanceMaterialization) -> Result<Self> {
        let prior = write.prior();
        let (id, occurred, learned_at, data, envelope) = write.into_parts();
        let body = crate::claim::validate_claim_body_and_decode(&data, true)?;
        let record = crate::provenance::decode_edge_provenance_body(&body.value)?;
        let class =
            crate::provenance::resolve_persisted_actor_class(&record, body.evidence.as_ref())?;
        if body.predicate != crate::provenance::PREDICATE_EDGE_PROVENANCE
            || envelope.actor() != WriteActor::new(record.actor_entity_ref, class)
            || body.source != Some(envelope.source()) && body.source.is_some()
            || body.approval != envelope.approval()
            || envelope.provenance().value() != &body.value
            || envelope.lineage() != &SourceLineage::of(envelope.source())
        {
            return Err(binding_error());
        }
        Ok(Self {
            id,
            occurred,
            learned_at,
            data,
            reserved: true,
            envelope,
            prior,
            approval: false,
        })
    }

    /// Only closing the current active row is admitted. No actor or evidence
    /// argument exists. The body must be identical except for life and valid_to.
    pub(crate) fn lifecycle(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<Option<Self>> {
        let BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        } = op
        else {
            return Err(binding_error());
        };
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(binding_error());
        }
        let prior = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        let Some(valid_to) = next.valid_to else {
            return Err(binding_error());
        };
        if valid_to < header.occurred_start {
            return Err(Error::InvalidTimeRange {
                start: header.occurred_start,
                end: valid_to,
            });
        }
        let mut expected = prior.clone();
        expected.lifecycle = next.lifecycle;
        expected.valid_to = next.valid_to;
        if prior.lifecycle != ClaimLifecycleStatus::Active
            || !matches!(
                next.lifecycle,
                ClaimLifecycleStatus::Retracted | ClaimLifecycleStatus::Superseded
            )
            || encode_claim_body(&expected)? != *data
            || occurred.start != header.occurred_start
            || occurred.end != valid_to
            || *learned_at != header.learned_at
        {
            return Err(binding_error());
        }
        let Some(envelope) = lifecycle_envelope(store, txn, id, &prior)? else {
            return Ok(None);
        };
        let binding = Self {
            id: *id,
            occurred: *occurred,
            learned_at: *learned_at,
            data: data.clone(),
            reserved: false,
            envelope,
            prior: Some(row_digest(&raw)),
            approval: false,
        };
        // Retraction records a gate decision before consuming the Put. Check
        // the reconstructed actor now, before any non-transactional metrics.
        binding.validate_actor(store, txn)?;
        Ok(Some(binding))
    }

    /// Canonical lifecycle validator supplies both an optional author binding
    /// and a sealed confidence-transition proof. Raw claims need no author
    /// binding, but still carry the proof of their exact closure operation.
    pub(crate) fn verified_lifecycle(
        store: &Store,
        txn: &heed::RoTxn<'_>,
        op: &BatchOp,
    ) -> Result<(Option<Self>, super::VerifiedClaimTransition)> {
        let binding = Self::lifecycle(store, txn, op)?;
        let proof = super::VerifiedClaimTransition::after_validation(store, txn, op)?;
        Ok((binding, proof))
    }

    /// Admit only a current-row demotion and its exact ClaimOf weight update.
    /// This does not widen the operation allowlist of other materializations.
    pub(crate) fn apply_demotion(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        ops: Vec<BatchOp>,
    ) -> Result<()> {
        let Some(BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }) = ops.first()
        else {
            return Err(binding_error());
        };
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || occurred.start != header.occurred_start
            || *learned_at != header.learned_at
        {
            return Err(binding_error());
        }
        let prior = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        let next = crate::claim::validate_claim_body_and_decode(data, false)?;
        let expected = demotion_body(&vault.store, txn, id, &prior, &next, &ops[1..])?;
        if encode_claim_body(&expected)? != *data {
            return Err(binding_error());
        }
        let transition =
            super::VerifiedClaimTransition::after_validated_demotion(&vault.store, txn, &ops)?;
        let mut bindings = Vec::new();
        if let Some(envelope) = lifecycle_envelope(&vault.store, txn, id, &prior)? {
            let binding = Self {
                id: *id,
                occurred: *occurred,
                learned_at: *learned_at,
                data: data.clone(),
                reserved: false,
                envelope,
                prior: Some(row_digest(&raw)),
                approval: false,
            };
            binding.validate_actor(&vault.store, txn)?;
            bindings.push(binding);
        }
        // No binding still means the existing first-party local policy, not
        // authority inferred from evidence. The pipeline refreshes a consumed
        // binding from the finalized row, atomically with the edge update.
        super::apply_ops_with_gate_mode(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            ops,
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(false, false)
                .with_claim_materializations(bindings)
                .with_verified_claim_transitions(vec![transition]),
        )
    }

    /// Re-gate an exact parked replacement as Auto under its attested author.
    /// The caller checks the deferred content/frontier binding and performs
    /// closure in this same transaction. No arbitrary Put may use this path.
    pub(crate) fn apply_deferred_auto_grant(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        id: &EntityId,
        checker: Option<&crate::llm::BoundedAutoChecker>,
    ) -> Result<Option<crate::gate::RecordedClaimGateDecision>> {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(binding_error());
        }
        let prior = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        if prior.approval != ClaimApprovalStatus::Proposed {
            return Err(binding_error());
        }
        let mut envelope =
            lifecycle_envelope(&vault.store, txn, id, &prior)?.ok_or(binding_error())?;
        envelope = WriteEnvelope::with_lineage(
            envelope.actor(),
            envelope.source(),
            envelope.provenance().clone(),
            ClaimApprovalStatus::Auto,
            envelope.lineage().clone(),
        );
        let mut next = prior;
        next.approval = ClaimApprovalStatus::Auto;
        let data = encode_claim_body(&next)?;
        let occurred = crate::temporal::TimeRange {
            start: header.occurred_start,
            end: header.occurred_end,
        };
        let binding = Self {
            id: *id,
            occurred,
            learned_at: header.learned_at,
            data: data.clone(),
            reserved: false,
            envelope,
            prior: Some(row_digest(&raw)),
            approval: false,
        };
        binding.validate_actor(&vault.store, txn)?;
        let machine = crate::authority::machine_claim_needs_history(&vault.store, txn, &next)?;
        let policy = crate::gate::resolve_policy_manifest(&vault.store, txn)?;
        let mut decision = None;
        crate::gate::check_claim_policy_for_write_with_record(
            &vault.store,
            txn,
            id,
            crate::gate::ClaimGateWrite {
                body: &next,
                envelope: Some(&binding.envelope),
                auto_checker: checker,
                defer_metrics_until_commit: true,
                transition: None,
            },
            &policy,
            crate::gate::GateWriteMode {
                record_decision: true,
                persist_pending_consent: false,
                resolve_pending: false,
                can_resolve_pending_consent: true,
                include_source_in_gate_input: false,
            },
            &mut decision,
        )?;
        let preflight_ids = std::collections::HashMap::from([(
            *id,
            VecDeque::from([decision
                .as_ref()
                .map(crate::gate::RecordedClaimGateDecision::decision_id)]),
        )]);
        if machine {
            // A MACHINE claim's grant is its author's signed Approve event,
            // which the fold records as this Auto grant.
            let granted = crate::claim::transition::stage_machine_transition_as(
                vault,
                txn,
                *id,
                crate::claim::transition::ClaimTransitionKind::Approve,
                crate::claim::transition::TransitionDelta::None,
                binding.envelope.actor(),
                vault.store.clock.now_recorded_at(),
            )?;
            if encode_claim_body(&granted)? != data {
                return Err(binding_error());
            }
        }
        super::apply_ops_with_gate_mode(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![BatchOp::Put {
                id: *id,
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                occurred,
                learned_at: header.learned_at,
                data,
                allow_maintenance: false,
                allow_reserved_predicate: false,
                hub_sync_imported: false,
            }],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            ApplyOpsGateMode::new(false, false)
                .with_claim_materializations(vec![binding])
                .with_preflight_gate_decision_ids(preflight_ids),
        )?;
        Ok(decision)
    }

    /// Admit only the current row's unamended approval: the stored body with
    /// its approval set to Approved. An approval never removes the author, so
    /// the author binding is rebuilt from the stored row and refreshed on the
    /// approved row. The Put stays the approver's write: it is gated and
    /// audited as before, never against the author's own approval ceiling.
    pub(crate) fn apply_approval(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        op: BatchOp,
        persist_pending: bool,
        approver: Option<crate::WriteActor>,
    ) -> Result<()> {
        Self::apply_approval_inner(vault, txn, op, persist_pending, None, approver)
    }

    pub(crate) fn apply_refinement_approval(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        op: BatchOp,
        proof: crate::skill_hub::RefinementAdmissionProof,
    ) -> Result<()> {
        Self::apply_approval_inner(vault, txn, op, false, Some(proof), None)
    }

    fn apply_approval_inner(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        mut op: BatchOp,
        persist_pending: bool,
        proof: Option<crate::skill_hub::RefinementAdmissionProof>,
        approver: Option<crate::WriteActor>,
    ) -> Result<()> {
        let BatchOp::Put {
            id,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at,
            data,
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        } = &mut op
        else {
            return Err(binding_error());
        };
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, id)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM
            || occurred.start != header.occurred_start
            || occurred.end != header.occurred_end
            || *learned_at != header.learned_at
        {
            return Err(binding_error());
        }
        let prior = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], true)?;
        let mut expected = prior.clone();
        expected.approval = ClaimApprovalStatus::Approved;
        if encode_claim_body(&expected)? != *data {
            return Err(binding_error());
        }
        if crate::authority::machine_claim_needs_history(&vault.store, txn, &prior)? {
            let now = vault.store.clock.now_recorded_at();
            let approved = match approver {
                Some(actor) => crate::claim::transition::stage_machine_transition_as(
                    vault,
                    txn,
                    *id,
                    crate::claim::transition::ClaimTransitionKind::Approve,
                    crate::claim::transition::TransitionDelta::None,
                    actor,
                    now,
                )?,
                None => crate::claim::transition::stage_owner_machine_transition(
                    vault,
                    txn,
                    *id,
                    crate::claim::transition::ClaimTransitionKind::Approve,
                    crate::claim::transition::TransitionDelta::None,
                    now,
                )?,
            };
            *data = encode_claim_body(&approved)?;
        }
        let mut bindings = Vec::new();
        if let Some(envelope) = lifecycle_envelope(&vault.store, txn, id, &prior)? {
            let binding = Self {
                id: *id,
                occurred: *occurred,
                learned_at: *learned_at,
                data: data.clone(),
                reserved: false,
                envelope,
                prior: Some(row_digest(&raw)),
                approval: true,
            };
            binding.validate_actor(&vault.store, txn)?;
            bindings.push(binding);
        }
        let transition = super::VerifiedClaimTransition::after_validation(&vault.store, txn, &op)?;
        super::apply_ops_with_gate_mode(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            vec![op],
            vault
                .text_index_trusted
                .load(std::sync::atomic::Ordering::Acquire),
            match proof {
                Some(proof) => ApplyOpsGateMode::new(false, persist_pending)
                    .with_claim_materializations(bindings)
                    .with_verified_claim_transitions(vec![transition])
                    .with_refinement_admission(proof),
                None => ApplyOpsGateMode::new(false, persist_pending)
                    .with_claim_materializations(bindings)
                    .with_verified_claim_transitions(vec![transition]),
            },
        )
    }

    pub(super) fn matches_op(&self, op: &BatchOp) -> bool {
        matches!(op, BatchOp::Put { id, entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred, learned_at, data, allow_maintenance: false,
            allow_reserved_predicate, hub_sync_imported: false }
            if *id == self.id && *occurred == self.occurred && *learned_at == self.learned_at
                && *data == self.data && *allow_reserved_predicate == self.reserved)
    }

    pub(crate) fn envelope(&self) -> &WriteEnvelope {
        &self.envelope
    }

    /// The envelope the Put is gated and audited under; none for an approval.
    pub(super) fn gate_envelope(&self) -> Option<&WriteEnvelope> {
        (!self.approval).then_some(&self.envelope)
    }

    pub(super) fn validate_actor(&self, store: &Store, txn: &heed::RoTxn<'_>) -> Result<()> {
        let current = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &self.id)?;
        if current.as_ref().map(|raw| row_digest(raw)) != self.prior {
            return Err(binding_error());
        }
        if !self.reserved {
            let authored = AUTHORED.get(store, txn, &self.id)?;
            if authored != self.prior {
                return Err(binding_error());
            }
        }
        crate::gate::validate_write_envelope(&self.envelope)?;
        let actor = self.envelope.actor();
        let raw = crate::ports::EntityStoreRead::port_entity_raw(store, txn, &actor.entity_ref())?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        crate::provenance::validate_actor_class(header.entity_type, actor.actor_class())
    }
}

/// Consumes only the next exact binding, then validates its current authority.
pub(super) fn consume_claim_materialization(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    claim_materializations: &mut VecDeque<ClaimMaterialization>,
    op: &BatchOp,
    origin: BaseWriteOrigin<'_>,
) -> Result<Option<ClaimMaterialization>> {
    if claim_materializations
        .front()
        .is_some_and(|binding| binding.matches_op(op))
    {
        let binding = claim_materializations
            .pop_front()
            .expect("matched front binding");
        binding.validate_actor(store, txn)?;
        reject_overlay_member_base_write(store, &binding.envelope().actor().entity_ref(), origin)?;
        Ok(Some(binding))
    } else if !claim_materializations.is_empty()
        && matches!(
            op,
            BatchOp::Put {
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                ..
            }
        )
    {
        Err(Error::InvalidClaimBody(
            "claim materialization operation mismatch",
        ))
    } else {
        Ok(None)
    }
}

fn row_digest(raw: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(raw).into()
}

fn binding_error() -> Error {
    Error::InvalidClaimBody("claim materialization binding mismatch")
}

/// Binds a gated ClaimCandidate or a consumed lifecycle binding. An unbound
/// write invalidates any prior authored digest.
/// Read the finalized row, including its body and metadata, rather than the
/// pre-serialization candidate. A newly authorized writer replaces the prior
/// binding atomically; the old writer's sealed operation still pins its prior
/// row and therefore cannot consume the new writer's authority.
pub(super) fn record_committed_claim(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
    authored: bool,
) -> Result<()> {
    if !authored {
        return invalidate_authored_claim(store, txn, id);
    }
    let raw =
        crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?.ok_or(binding_error())?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(binding_error());
    }
    let digest = row_digest(&raw);
    AUTHORED.put(store, txn, id, &digest)?;
    Ok(())
}

/// A successful unbound write must not inherit an earlier writer's authority,
/// even when it copies that writer's evidence verbatim. Rejected writes do not
/// reach this point, and transaction rollback restores the prior binding.
pub(super) fn invalidate_authored_claim(
    store: &Store,
    txn: &mut heed::RwTxn<'_>,
    id: &EntityId,
) -> Result<()> {
    AUTHORED.delete(store, txn, id)?;
    Ok(())
}

/// Evidence alone grants nothing. The private host-written digest must match
/// before the current claim's immutable axes can reconstruct an envelope.
fn lifecycle_envelope(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<Option<WriteEnvelope>> {
    let Some(digest) = AUTHORED.get(store, txn, id)? else {
        return Ok(None);
    };
    let raw =
        crate::ports::EntityStoreRead::port_entity_raw(store, txn, id)?.ok_or(binding_error())?;
    let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
    if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM || digest != row_digest(&raw) {
        return Err(binding_error());
    }
    let authored = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
    if encode_claim_body(body)? != encode_claim_body(&authored)? {
        return Err(binding_error());
    }
    envelope_from_evidence(&authored, body).map(Some)
}

/// Reconstructs the writer's envelope from the authenticated `authored`
/// row's evidence axes, with `body`'s current approval and session tag.
fn envelope_from_evidence(authored: &ClaimBody, body: &ClaimBody) -> Result<WriteEnvelope> {
    let Value::Map(entries) = authored.evidence.as_ref().ok_or(binding_error())? else {
        return Err(binding_error());
    };
    let get = |key: &str| -> Result<&Value> {
        let mut values = entries.iter().filter(|(k, _)| k.as_str() == Some(key));
        let value = &values.next().ok_or(binding_error())?.1;
        if values.next().is_some() {
            return Err(binding_error());
        }
        Ok(value)
    };
    let Value::Binary(actor_bytes) = get("actor_entity_ref")? else {
        return Err(binding_error());
    };
    let actor = EntityId::from_bytes(
        actor_bytes
            .as_slice()
            .try_into()
            .map_err(|_| binding_error())?,
    )?;
    let class = match get("actor_class")?.as_u64() {
        Some(0) => crate::edge::EdgeActorClass::Human,
        Some(1) => crate::edge::EdgeActorClass::Agent,
        Some(2) => crate::edge::EdgeActorClass::System,
        _ => return Err(binding_error()),
    };
    let source = authored.source.ok_or(binding_error())?;
    let mut lineage = SourceLineage::of(source);
    if entries.iter().any(|(k, _)| k.as_str() == Some("lineage")) {
        let Value::Array(sources) = get("lineage")? else {
            return Err(binding_error());
        };
        for value in sources {
            lineage = lineage.with(
                ClaimSource::parse(value.as_str().ok_or(binding_error())?).ok_or(binding_error())?,
            );
        }
    }
    let mut envelope = WriteEnvelope::with_lineage(
        WriteActor::new(actor, class),
        source,
        WriteProvenance::new(get("provenance")?.clone())?,
        body.approval,
        lineage,
    );
    if let Some(tag) = &body.session_tag {
        envelope = envelope.with_session_tag(tag);
    }
    Ok(envelope)
}

/// The locally attested writer of this exact row. Evidence copied through a
/// raw or replicated Put is not an authorship capability.
pub(crate) fn authenticated_claim_author_in_txn(
    store: &Store,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<Option<WriteActor>> {
    Ok(lifecycle_envelope(store, txn, id, body)?.map(|envelope| envelope.actor()))
}

/// The operation list is checked as a whole, then again at consumption. Missing,
/// duplicate or extra envelopes cannot shift a later operation's actor.
pub(crate) fn apply_owner_bound_claim_puts(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ops: Vec<BatchOp>,
    bindings: Vec<ClaimMaterialization>,
    persist_pending: bool,
) -> Result<()> {
    apply_owner_bound_claim_puts_with_transitions(
        vault,
        txn,
        ops,
        bindings,
        Vec::new(),
        persist_pending,
    )
}

pub(crate) fn apply_owner_bound_claim_puts_with_transitions(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    ops: Vec<BatchOp>,
    bindings: Vec<ClaimMaterialization>,
    transitions: Vec<super::VerifiedClaimTransition>,
    persist_pending: bool,
) -> Result<()> {
    let mut remaining = bindings.iter();
    for op in &ops {
        if matches!(
            op,
            BatchOp::Put {
                entity_type: crate::registry::ENTITY_TYPE_CLAIM,
                ..
            }
        ) {
            if !remaining
                .next()
                .is_some_and(|binding| binding.matches_op(op))
            {
                return Err(binding_error());
            }
        } else if !matches!(
            op,
            BatchOp::Edge {
                kind: crate::edge::EdgeKind::ClaimOf,
                ..
            } | BatchOp::EdgeWithCreatedAt {
                kind: crate::edge::EdgeKind::Supersedes,
                ..
            }
        ) {
            return Err(binding_error());
        }
    }
    if remaining.next().is_some() {
        return Err(binding_error());
    }
    super::apply_ops_with_gate_mode(
        &vault.store,
        &vault.config,
        &vault.analyzer,
        txn,
        ops,
        vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire),
        ApplyOpsGateMode::new(false, persist_pending)
            .with_claim_materializations(bindings)
            .with_verified_claim_transitions(transitions),
    )
}

mod demotion;
mod succession;
use demotion::demotion_body;

#[cfg(test)]
mod tests;
