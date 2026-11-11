//! Stored support citations projected with the extraction result's own reader.

use crate::EntityId;
use crate::claim::ScopedRead;
use crate::dreamer_consolidation::{
    VerifiedLocator, decode_consolidation_evidence, decode_verified_citations,
};
use crate::dreamer_promotion::public_evidence_refs;
use crate::edge::EdgeKind;
use crate::memory::Memory;
use crate::ports::{EdgeDirection, EdgeStoreRead};
use crate::provenance::{EdgeRef, SupersessionStatus};

pub(super) fn append(
    memory: &Memory<'_>,
    lane: &ScopedRead<'_>,
    txn: &heed::RoTxn<'_>,
    head: EntityId,
    citations: &mut Vec<VerifiedLocator>,
) {
    // Optional attachment records cannot refuse an otherwise readable output.
    let Ok(edges) = memory.vault.store.port_edges(
        txn,
        &head,
        EdgeDirection::In,
        Some(EdgeKind::Supports),
        None,
    ) else {
        return;
    };
    for edge in edges {
        let Ok(edge) = edge else { continue };
        let subject = EdgeRef::new(edge.target, EdgeKind::Supports, head);
        if subject.source == head
            || !memory
                .vault
                .store
                .port_edge_consistent(txn, &subject.source, EdgeKind::Supports, &head)
                .unwrap_or(false)
        {
            continue;
        }
        let Ok(claims) = memory
            .vault
            .live_edge_provenance_claims_in_txn(txn, &subject, None)
        else {
            continue;
        };
        for claim in claims {
            if claim.record.supersession_status != SupersessionStatus::Confirmed {
                continue;
            }
            let Some(stored) = claim
                .wrapper
                .scope
                .as_ref()
                .and_then(rmpv::Value::as_map)
                .and_then(|fields| {
                    fields
                        .iter()
                        .find(|(key, _)| key.as_str() == Some("derived_evidence"))
                        .map(|(_, value)| value)
                })
            else {
                continue;
            };
            let Ok(Some(envelope)) = decode_consolidation_evidence(stored) else {
                continue;
            };
            if envelope.refs != [subject.source]
                || !envelope.chain.is_empty()
                || claim.wrapper.source != Some(envelope.source_meet)
            {
                continue;
            }
            let Ok(document_refs) = public_evidence_refs(Some(stored)) else {
                continue;
            };
            let Ok(attached) = decode_verified_citations(stored) else {
                continue;
            };
            if attached
                .iter()
                .any(|(locator, _, _)| locator.source_id != subject.source)
            {
                continue;
            }
            let Ok(document_sources) = document_refs
                .iter()
                .map(|reference| EntityId::from_hex(&reference.entity))
                .collect::<crate::Result<Vec<_>>>()
            else {
                continue;
            };
            let mut named = vec![head, claim.id, subject.source];
            named.extend(document_sources);
            for (locator, _, messages) in &attached {
                named.push(locator.source_id);
                named.extend(locator.claim_id);
                named.extend(messages.iter().map(|message| message.message));
            }
            named.sort_unstable();
            named.dedup();
            let Ok(readable) = lane.entities_readable_in_txn(txn, &named) else {
                continue;
            };
            if readable.iter().any(|readable| !readable) {
                continue;
            }
            memory.produced_from(named);
            // Compare stored locators before the public view drops frontier.
            for citation in attached {
                if !citations.iter().any(|prior| {
                    prior.0.source_id == citation.0.source_id
                        && prior.0.claim_id == citation.0.claim_id
                        && prior.0.byte_range == citation.0.byte_range
                        && prior.1 == citation.1
                        && prior.2 == citation.2
                }) {
                    citations.push(citation);
                }
            }
        }
    }
}
