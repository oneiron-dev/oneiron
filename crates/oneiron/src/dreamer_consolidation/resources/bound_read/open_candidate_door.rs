//! Native's outside-set candidate write for parity tests.
//!
//! Rebuilds the bound inputs as the routing door does, opens the same branch
//! and assembles with real `assemble_extracted`. The outside-set writes are
//! then sealed with real `prepare_write_verified`, and the one write is
//! prepared with real `prepare_promotion` under native provenance, without
//! writing, so a test can compare the claim another path wrote. No model is
//! asked.

use serde_json::{Value, json};

use super::open_conflict_door::with_native_assembly;
use crate::entity_id::EntityId;
use crate::error::{Error, Result};
use crate::vault::Vault;

/// Builds, without writing, the claim the one outside-set candidate
/// `operand` on the bound attempt at `now_ms` would land as, and returns it
/// as JSON.
///
/// Output holds the claim id, and from the prepared candidate's claim body
/// the predicate, subject, value, scope, source, confidence, world,
/// relationship, facet and project, with the candidate evidence: values and
/// scopes as lowercase hex of their encoded bytes, the rest as JSON. It also
/// holds the validity window, the learned time, and the approval the
/// envelope asks. A test commits the same operand through another path and
/// compares field by field. Provenance is native's and is not compared: the
/// other path stamps its own.
///
/// Operands that form a conflict, or that seal to anything but exactly one
/// plain write, are refused before any preparation.
///
/// # Errors
///
/// The vault's, operands the bound read refuses, operands that form a
/// native conflict or seal to anything but one write, a native promotion
/// refusal, and a claim that does not encode.
pub(crate) fn build_native_candidate_json(
    vault: &Vault,
    attempt_hex: &str,
    now_ms: u64,
    operand: &Value,
) -> Result<Value> {
    with_native_assembly(
        vault,
        attempt_hex,
        now_ms,
        std::slice::from_ref(operand),
        |attempt_id, actor, resources, assembled, _claims| {
            if !assembled.conflicts.is_empty() {
                return Err(Error::InvalidConfig(format!(
                    "the operands form {} native conflicts, not none",
                    assembled.conflicts.len()
                )));
            }
            let write =
                resources.prepare_write_verified(resources.scope(), assembled.candidates)?;
            if write.candidates.len() != 1 || !write.attachments.is_empty() {
                return Err(Error::InvalidConfig(format!(
                    "the operands seal to {} writes and {} attachments, not one outside-set write",
                    write.candidates.len(),
                    write.attachments.len()
                )));
            }
            let mut writes = write.candidates.into_iter();
            let candidate = writes.next().ok_or_else(|| {
                Error::InvalidConfig("the sealed write names no candidate".to_owned())
            })?;
            let mut evidences = write.candidate_evidence.into_iter();
            let evidence = evidences.next().ok_or_else(|| {
                Error::InvalidConfig("the sealed write names no evidence".to_owned())
            })?;
            let run = crate::dreamer_promotion::DreamerRunContext {
                run_id: crate::entity_id::bytes_to_hex_lower(attempt_id.as_bytes()),
                attempt_id,
                agent_actor: actor,
                now_ms,
            };
            let txn = vault.store.env.read_txn()?;
            let (prepared, claim_candidate) = crate::dreamer_promotion::prepare_promotion(
                vault,
                &txn,
                &run,
                candidate,
                Some(&evidence),
                &[],
                None,
            )
            .map_err(|rejection| {
                Error::InvalidConfig(format!(
                    "native promotion refused with kind {:?}",
                    rejection.kind
                ))
            })?;
            let default_facet = vault.default_facet_in_txn(&txn)?;
            let candidate_evidence = claim_candidate
                .evidence()
                .cloned()
                .unwrap_or(rmpv::Value::Nil);
            let mut evidence_bytes = Vec::new();
            rmpv::encode::write_value(&mut evidence_bytes, &candidate_evidence).map_err(|_| {
                Error::InvalidConfig(
                    "a native candidate evidence envelope does not encode".to_owned(),
                )
            })?;
            let body = claim_candidate.into_claim_body(&prepared.envelope, default_facet)?;
            let crate::ClaimSubject::Entity(subject) = body.subject else {
                return Err(Error::InvalidConfig(
                    "a native candidate names no entity subject".to_owned(),
                ));
            };
            let mut value_bytes = Vec::new();
            rmpv::encode::write_value(&mut value_bytes, &body.value).map_err(|_| {
                Error::InvalidConfig("a native candidate value does not encode".to_owned())
            })?;
            let scope_hex = body
                .scope
                .as_ref()
                .map(|scope| {
                    let mut bytes = Vec::new();
                    rmpv::encode::write_value(&mut bytes, scope).map_err(|_| {
                        Error::InvalidConfig("a native candidate scope does not encode".to_owned())
                    })?;
                    Ok(crate::entity_id::bytes_to_hex_lower(&bytes))
                })
                .transpose()?;
            Ok(json!({
                "claim": prepared.claim_id.to_hex(),
                "predicate": body.predicate,
                "subject": subject.to_hex(),
                "value_hex": crate::entity_id::bytes_to_hex_lower(&value_bytes),
                "scope_hex": scope_hex,
                "source": body.source.map(|source| source.as_str().to_owned()),
                "confidence": body.confidence,
                "world": body.world.map(|world| world.to_hex()),
                "relationship": body.rel.as_ref().map(|rel| {
                    rel.iter().map(EntityId::to_hex).collect::<Vec<_>>()
                }),
                "facet": body.scope_facet.to_hex(),
                "project": body.scope_project.to_hex(),
                "candidate_evidence_hex": crate::entity_id::bytes_to_hex_lower(&evidence_bytes),
                "occurred": {"start": prepared.occurred.start, "end": prepared.occurred.end},
                "learned_at": prepared.learned_at,
                "approval": body.approval.as_str(),
            }))
        },
    )
}
