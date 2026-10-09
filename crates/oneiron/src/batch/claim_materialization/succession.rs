//! Claim succession: a weakening or a facet fork births a new claim from its
//! predecessor's exact body, never rewriting the predecessor.

use super::demotion::successor_body;
use super::{ClaimMaterialization, binding_error, envelope_from_evidence, lifecycle_envelope};
use crate::batch::{ApplyOpsGateMode, BatchOp, ENTITY_METADATA_HEADER_LEN, EntityMetadataHeader};
use crate::claim::{ClaimBody, decode_claim_body, encode_claim_body};
use crate::error::{Error, Result};
use crate::write_envelope::WriteEnvelope;
use crate::{EntityId, Vault};

impl ClaimMaterialization {
    /// Admit only a claim successor whose body is its predecessor's with the
    /// one delta `succession` permits, plus its ClaimOf edge at the
    /// predecessor's current (possibly decayed) weight and its facet stamp:
    /// a weakening keeps the predecessor's `facet_of` edges, a fork wears its
    /// new mask's when asked to. The successor keeps the predecessor's
    /// attested writer. A MACHINE successor is re-signed by that writer's
    /// retained signer and gets its own signed birth. The caller links or
    /// closes the predecessor in the same txn.
    pub(crate) fn apply_successor(
        vault: &Vault,
        txn: &mut heed::RwTxn<'_>,
        predecessor: &EntityId,
        successor: &EntityId,
        succession: crate::claim::ClaimSuccession,
        now: u64,
    ) -> Result<()> {
        let raw = crate::ports::EntityStoreRead::port_entity_raw(&vault.store, txn, predecessor)?
            .ok_or(Error::EntityNotFound)?;
        let header = EntityMetadataHeader::parse(&raw).ok_or(binding_error())?;
        if header.entity_type != crate::registry::ENTITY_TYPE_CLAIM {
            return Err(binding_error());
        }
        let prior = decode_claim_body(&raw[ENTITY_METADATA_HEADER_LEN..], false)?;
        let mut next = successor_body(&prior, succession)?;
        let mut claim_of = None;
        if let crate::claim::ClaimSubject::Entity(subject) = prior.subject {
            let mut weight = None;
            for entry in crate::ports::EdgeStoreRead::port_edges(
                &vault.store,
                txn,
                predecessor,
                crate::ports::EdgeDirection::Out,
                Some(crate::edge::EdgeKind::ClaimOf),
                None,
            )? {
                let edge = entry?;
                if edge.target == subject && weight.replace(edge.weight).is_some() {
                    return Err(binding_error());
                }
            }
            claim_of = Some((subject, weight.ok_or(binding_error())?));
        }
        let stamps = match succession {
            crate::claim::ClaimSuccession::Weakening { .. } => {
                let mut stamps = Vec::new();
                for entry in crate::ports::EdgeStoreRead::port_edges(
                    &vault.store,
                    txn,
                    predecessor,
                    crate::ports::EdgeDirection::Out,
                    Some(crate::edge::EdgeKind::FacetOf),
                    None,
                )? {
                    let edge = entry?;
                    stamps.push((edge.target, edge.weight));
                }
                stamps
            }
            crate::claim::ClaimSuccession::Fork { facet, stamp } => {
                stamp.then_some((facet, 1.0)).into_iter().collect()
            }
        };
        let signed = crate::authority::machine_claim_needs_history(&vault.store, txn, &prior)?;
        let mut envelope = match lifecycle_envelope(&vault.store, txn, predecessor, &prior)? {
            Some(envelope) => Some(envelope),
            None if signed => Some(verified_machine_envelope(vault, txn, predecessor, &prior)?),
            None => None,
        };
        if signed {
            let envelope = envelope.as_mut().ok_or(binding_error())?;
            vault.resign_machine_successor_in_txn(txn, successor, &mut next, envelope)?;
        }
        let occurred = crate::temporal::TimeRange {
            start: header.occurred_start,
            end: now,
        };
        let data = encode_claim_body(&next)?;
        let mut ops = vec![BatchOp::Put {
            id: *successor,
            entity_type: crate::registry::ENTITY_TYPE_CLAIM,
            occurred,
            learned_at: now,
            data: data.clone(),
            allow_maintenance: false,
            allow_reserved_predicate: false,
            hub_sync_imported: false,
        }];
        if let Some((subject, weight)) = claim_of {
            ops.push(BatchOp::Edge {
                src: *successor,
                kind: crate::edge::EdgeKind::ClaimOf,
                tgt: subject,
                weight,
                vad: crate::affect::Vad::NEUTRAL,
            });
        }
        for (facet, weight) in stamps {
            ops.push(BatchOp::Edge {
                src: *successor,
                kind: crate::edge::EdgeKind::FacetOf,
                tgt: facet,
                weight,
                vad: crate::affect::Vad::NEUTRAL,
            });
        }
        let transition = crate::batch::VerifiedClaimTransition::after_validated_succession(
            &vault.store,
            txn,
            predecessor,
            &ops[0],
        )?;
        let mut bindings = Vec::new();
        if let Some(envelope) = envelope.clone() {
            let binding = Self {
                id: *successor,
                occurred,
                learned_at: now,
                data,
                reserved: false,
                envelope,
                prior: None,
                approval: false,
            };
            binding.validate_actor(&vault.store, txn)?;
            bindings.push(binding);
        }
        let text_index_trusted = vault
            .text_index_trusted
            .load(std::sync::atomic::Ordering::Acquire);
        crate::batch::apply_ops_with_gate_mode(
            &vault.store,
            &vault.config,
            &vault.analyzer,
            txn,
            ops,
            text_index_trusted,
            // A fresh fork is a birth like any other, so an Auto critical
            // claim gets its critical-confirm attachment. A weakening lands
            // only once a critical demotion's owner clear has settled.
            ApplyOpsGateMode::new(
                false,
                matches!(succession, crate::claim::ClaimSuccession::Fork { .. }),
            )
            .with_claim_materializations(bindings)
            .with_verified_claim_transitions(vec![transition]),
        )?;
        match envelope {
            Some(envelope) if signed => {
                crate::claim::history_store::stage_machine_birth_after_candidate(
                    &vault.store,
                    &vault.config,
                    &vault.analyzer,
                    txn,
                    *successor,
                    &next,
                    &envelope,
                    occurred,
                    now,
                    text_index_trusted,
                    false,
                )
            }
            _ => Ok(()),
        }
    }
}

/// A MACHINE claim's signed birth binds its evidence, so a row with no local
/// authorship digest (a replicated one) still names its writer once its
/// trusted signed history verifies against the current row.
fn verified_machine_envelope(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    id: &EntityId,
    body: &ClaimBody,
) -> Result<WriteEnvelope> {
    let fold = crate::authority::authority_fold_readonly_for_store_in_txn(
        &vault.store,
        vault.config.privacy.posture,
        txn,
    )?;
    if !crate::authority::machine_claim_read_admitted(&vault.store, txn, &fold, id, body)? {
        return Err(binding_error());
    }
    envelope_from_evidence(body, body)
}
