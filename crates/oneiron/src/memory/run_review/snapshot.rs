use super::*;
use crate::claim::{ClaimApprovalStatus, ClaimLifecycleStatus};
use crate::ports::{EntityStoreRead, TombstoneStoreRead};

pub(super) fn claim_author(body: &crate::claim::ClaimBody) -> MemoryResult<EntityId> {
    if body.predicate == crate::provenance::PREDICATE_EDGE_PROVENANCE {
        return Ok(crate::provenance::decode_edge_provenance_body(&body.value)?.actor_entity_ref);
    }
    super::super::claim_author(body)
        .ok_or_else(|| MemoryError::bad_request("the claim has no authenticated author"))
}

pub(super) fn binding(
    memory: &Memory<'_>, txn: &heed::RoTxn<'_>, member: &RunReviewChange,
) -> MemoryResult<(Vec<u8>, RunChangeVerdict)> {
    let vault = memory.vault();
    match member {
        RunReviewChange::Claim { claim_ref } | RunReviewChange::Edge { provenance_ref: claim_ref } => {
            let id = EntityId::from_hex(claim_ref)?;
            if vault.store.port_deletion_state(txn, &id)?.deleted {
                return Err(MemoryError::not_found("review claim was deleted"));
            }
            let body = vault.get_claim_in_txn(txn, &id)?
                .ok_or_else(|| MemoryError::not_found("review claim is absent"))?;
            if matches!(member, RunReviewChange::Edge { .. })
                && body.predicate != crate::provenance::PREDICATE_EDGE_PROVENANCE {
                return Err(MemoryError::bad_request("an edge change names its provenance claim"));
            }
            let author = claim_author(&body)?;
            if body.approval == ClaimApprovalStatus::Proposed && author == memory.actor() {
                return Err(MemoryError::bad_request("a proposal's opener never settles it"));
            }
            let raw = vault.store.port_entity_record(txn, &id)?
                .ok_or_else(|| MemoryError::not_found("review claim is absent"))?.encode();
            let pending = vault.store.pending_gate_consent_in_txn(txn, &id)?;
            let bytes = serde_json::to_vec(&(raw, pending))
                .map_err(|_| MemoryError::bad_request("claim review cannot be encoded"))?;
            let verdict = if body.approval == ClaimApprovalStatus::Rejected
                || body.lifecycle != ClaimLifecycleStatus::Active { RunChangeVerdict::Rejected }
                else if body.approval == ClaimApprovalStatus::Proposed { RunChangeVerdict::Waiting }
                else { RunChangeVerdict::Landed };
            Ok((bytes, verdict))
        }
        RunReviewChange::Note { note_ref, fork_ref } => {
            let (_, bytes) = crate::note::run_note_review_in_txn(vault, txn,
                EntityId::from_hex(note_ref)?, EntityId::from_hex(fork_ref)?)?;
            Ok((bytes, RunChangeVerdict::Waiting))
        }
        RunReviewChange::Topology { event_ref } => {
            let id = EntityId::from_hex(event_ref)?;
            let event = vault.identity_topology_event_in_txn(txn, &id)?
                .ok_or_else(|| MemoryError::not_found("topology event is absent"))?;
            use crate::identity_topology::StoredIdentityOpAction;
            if !matches!(event.action, StoredIdentityOpAction::Merge { .. }
                | StoredIdentityOpAction::Split { .. } | StoredIdentityOpAction::Facet { .. }) {
                return Err(MemoryError::bad_request("only merge, split and facet events join run review"));
            }
            if event.approval == ClaimApprovalStatus::Proposed
                && event.actor.is_some_and(|actor| actor.entity_ref() == memory.actor()) {
                return Err(MemoryError::bad_request("a proposal's opener never settles it"));
            }
            let raw = vault.store.port_entity_record(txn, &id)?
                .ok_or_else(|| MemoryError::not_found("topology event is absent"))?.encode();
            // Resolution, admission and retirement are part of the review,
            // not only the immutable event body.
            let events = vault.identity_topology_events_in_txn(txn)?;
            let mut bytes = raw;
            for event in events {
                bytes.extend_from_slice(event.event_id.as_bytes());
                let raw = vault.store.port_entity_record(txn, &event.event_id)?
                    .ok_or_else(|| MemoryError::not_found("topology ledger member is absent"))?;
                bytes.extend_from_slice(blake3::hash(&raw.encode()).as_bytes());
            }
            Ok((bytes, if event.approval == ClaimApprovalStatus::Proposed {
                RunChangeVerdict::Waiting
            } else { RunChangeVerdict::Landed }))
        }
        RunReviewChange::ExternalEffect { receipt_ref } => {
            let id = receipt_ref.strip_prefix("gate:")
                .ok_or_else(|| MemoryError::bad_request("external effect names its gate: receipt"))?;
            let id = crate::store::GateDecisionId::from_bytes(*EntityId::from_hex(id)?.as_bytes());
            let record = vault.store.gate_decision_in_txn(txn, id)?
                .filter(|record| record.content_kind == "external_effect" && record.redacted_at.is_none())
                .ok_or_else(|| MemoryError::not_found("external-effect gate receipt is absent"))?;
            Ok((serde_json::to_vec(&record)
                .map_err(|_| MemoryError::bad_request("effect receipt cannot be encoded"))?,
                RunChangeVerdict::Landed))
        }
        RunReviewChange::Delete { entity_ref } | RunReviewChange::Erase { entity_ref } => {
            let id = EntityId::from_hex(entity_ref)?;
            if !vault.store.port_deletion_state(txn, &id)?.deleted {
                return Err(MemoryError::bad_request("the change has no applied deletion"));
            }
            let hard = vault.store.port_deletion_marker(txn,
                crate::ports::DeletionMarker::HardDelete, &id)?;
            if matches!(member, RunReviewChange::Erase { .. }) != hard.is_some() {
                return Err(MemoryError::bad_request("the requested undo class does not match the deletion"));
            }
            let mut bytes = id.as_bytes().to_vec();
            bytes.extend(hard.unwrap_or_default());
            Ok((bytes, RunChangeVerdict::Landed))
        }
    }
}

pub(super) fn review_in_txn(
    memory: &Memory<'_>, txn: &heed::RoTxn<'_>, input: &RunReviewRequest,
) -> MemoryResult<RunReview> {
    let run = run_key(&input.run_id)?;
    if input.changes.is_empty() {
        return Err(MemoryError::bad_request("a review needs an explicit nonempty change set"));
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut hash = blake3::Hasher::new_derive_key("oneiron.run-review.v1");
    let request = serde_json::to_vec(input)
        .map_err(|_| MemoryError::bad_request("review cannot be encoded"))?;
    hash.update(&request);
    hash.update(&crate::gate::resolve_policy_manifest(&memory.vault().store, txn)?.read_frontier_hash()?);
    let mut changes = Vec::new();
    for member in &input.changes {
        if !seen.insert(member.change()) {
            return Err(MemoryError::bad_request("a review repeats a change"));
        }
        let (bytes, verdict) = binding(memory, txn, member)?;
        hash.update(&(bytes.len() as u64).to_be_bytes());
        hash.update(&bytes);
        changes.push(RunChangeOutcome { change: member.change().to_owned(), verdict, receipt: None });
    }
    let read_refs: Vec<_> = input.changes.iter().map(|m| m.change().to_owned()).collect();
    Ok(RunReview {
        run_id: run, review_id: hash.finalize().to_hex().to_string(), changes,
        explainer: RunReviewExplainer {
            text: read_refs.iter().map(|reference| format!("Review {reference}"))
                .collect::<Vec<_>>().join("\n"),
            read_refs,
        },
    })
}
