//! OF-063 (FIX 1218): the typed record refs a CLAIM body names, judged under
//! its writer's own scoped read in the final write's own snapshot.
//!
//! Only declared record-bearing slots are read: the subject (an entity, or an
//! edge under its pair admission), and in the evidence the consolidation
//! envelope's refs, record hops and verified locators and the public
//! `evidence_refs[].entity` citations. They are read at the body's top level
//! (a raw body) or under the stamp's `candidate_evidence` and
//! `carried_evidence`. An evidence value that decodes as none of these names
//! no record: opaque evidence is never scanned for ids. WORLD and
//! RELATIONSHIP scope ids are not record refs and get no existence check (a
//! claim may name one before its row exists). Invented, missing, malformed
//! and unreadable are one unresolved result; a read that fails is an error.

use rmpv::Value;

use crate::claim::{ClaimBody, ClaimSubject, ScopedRead};
use crate::dreamer_consolidation::{
    ConsolidationProvenanceHopKind, decode_consolidation_evidence, decode_verified_locators,
};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::gate::record_references::{NamedRecordRef, validate_record_references_with};
use crate::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    WRITE_ENVELOPE_EVIDENCE_CARRIED_KEY, envelope_carried_evidence,
};

/// The field pointer of the first typed record ref `body` names that does
/// not resolve for `reader` in `txn`; `None` when every one does.
pub(super) fn unresolved_claim_reference(
    reader: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    body: &ClaimBody,
) -> Result<Option<String>> {
    if !reader.claim_edge_subject_admitted_in_txn(txn, &body.subject)? {
        return Ok(Some("/subject".to_owned()));
    }
    let refs = claim_record_references(body);
    let unresolved = validate_record_references_with(&refs, |reference| {
        let Ok(id) = EntityId::from_hex(reference) else {
            return Ok(false);
        };
        Ok(reader
            .entities_readable_in_txn(txn, &[id])?
            .first()
            .copied()
            .unwrap_or(false))
    })?;
    Ok(unresolved.map(str::to_owned))
}

/// Every typed record ref `body` declares, at its slot's pointer, in slot
/// order. An Edge subject is judged by its pair admission, not here.
fn claim_record_references(body: &ClaimBody) -> Vec<NamedRecordRef> {
    let mut refs = Vec::new();
    if let ClaimSubject::Entity(subject) = body.subject {
        push(&mut refs, "/subject".to_owned(), &subject);
    }
    let Some(evidence) = body.evidence.as_ref() else {
        return refs;
    };
    if stamped(evidence) {
        if let Some(candidate) = field(evidence, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY) {
            evidence_references(
                &format!("/evidence/{WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY}"),
                candidate,
                &mut refs,
            );
        }
        if let Some(carried) = envelope_carried_evidence(evidence) {
            evidence_references(
                &format!("/evidence/{WRITE_ENVELOPE_EVIDENCE_CARRIED_KEY}"),
                carried,
                &mut refs,
            );
        }
    } else {
        evidence_references("/evidence", evidence, &mut refs);
    }
    refs
}

/// The record refs one evidence value declares at `at`: a consolidation
/// envelope's refs, record hops and verified locators, and public citations.
fn evidence_references(at: &str, evidence: &Value, refs: &mut Vec<NamedRecordRef>) {
    if let Ok(Some(envelope)) = decode_consolidation_evidence(evidence) {
        for (index, id) in envelope.refs.iter().enumerate() {
            push(refs, format!("{at}/refs/{index}"), id);
        }
        for (index, hop) in envelope.chain.iter().enumerate() {
            // A peer hop names the answering actor, an identity rather than a
            // cited record, as the stamp's own actor is.
            if hop.kind != ConsolidationProvenanceHopKind::PeerActor {
                push(refs, format!("{at}/chain/{index}/entity_ref"), &hop.entity_ref);
            }
        }
        if field(evidence, "locators").is_some()
            && let Ok(locators) = decode_verified_locators(evidence)
        {
            for (index, (locator, _)) in locators.iter().enumerate() {
                push(
                    refs,
                    format!("{at}/locators/{index}/source_id"),
                    &locator.source_id,
                );
                if let Some(claim) = locator.claim_id {
                    push(refs, format!("{at}/locators/{index}/claim_id"), &claim);
                }
            }
        }
    }
    if let Ok(citations) = crate::dreamer_promotion::public_evidence_refs(Some(evidence)) {
        for (index, citation) in citations.into_iter().enumerate() {
            refs.push(NamedRecordRef {
                pointer: format!("{at}/evidence_refs/{index}/entity"),
                reference: citation.entity,
            });
        }
    }
}

fn push(refs: &mut Vec<NamedRecordRef>, pointer: String, id: &EntityId) {
    refs.push(NamedRecordRef {
        pointer,
        reference: id.to_hex(),
    });
}

/// Whether `evidence` is a write-envelope stamp rather than a raw body's own
/// evidence.
fn stamped(evidence: &Value) -> bool {
    field(evidence, WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY).is_some()
}

fn field<'v>(value: &'v Value, name: &str) -> Option<&'v Value> {
    let Value::Map(entries) = value else {
        return None;
    };
    entries
        .iter()
        .find(|(key, _)| key.as_str() == Some(name))
        .map(|(_, value)| value)
}
