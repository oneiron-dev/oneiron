//! Actor-scoped evidence and owner-authored voice reads, with exact revision pins.
use super::{Packet, RepresentationCitation, RepresentationRequest, invalid};
use crate::claim::{
    ScopedRead, ScopedReadActorKey, claim_evidence_admissible, decode_claim_body,
    session_claim_producer,
};
use crate::{ClaimSource, EntityId, Result, Vault};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationSource {
    pub claim: EntityId,
    pub revision: [u8; 32],
    pub text: String,
}
impl RepresentationSource {
    pub fn cite(&self, quote: impl Into<String>) -> RepresentationCitation {
        RepresentationCitation {
            claim: self.claim,
            revision: self.revision,
            quote: quote.into(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepresentationContext {
    pub request: RepresentationRequest,
    pub evidence: Vec<RepresentationSource>,
    pub voice: Vec<RepresentationSource>,
}
impl Vault {
    /// The model host receives only these admitted source texts. Claim bytes
    /// and owner voice are never read through an unscoped fallback.
    pub fn representation_context(
        &self,
        request: &RepresentationRequest,
    ) -> Result<RepresentationContext> {
        if request.evidence.is_empty()
            || request.voice.is_empty()
            || request.evidence.len() > 32
            || request.voice.len() > 8
            || [&request.verb, &request.channel, &request.target]
                .into_iter()
                .any(|s| s.trim().is_empty() || s.len() > 2048 || s.chars().any(char::is_control))
        {
            return Err(invalid());
        }
        crate::outbound::outbound_verb_contract(&request.channel, &request.verb)
            .map_err(|_| invalid())?;
        let actor = self.dreamer_authority()?.entity_ref();
        let reader = self.scoped_read(
            ScopedReadActorKey::with_actor_class(actor.to_hex(), "agent").ok_or_else(invalid)?,
        );
        let mut seen = BTreeSet::new();
        let evidence = request
            .evidence
            .iter()
            .map(|r| {
                if !seen.insert(r.claim) {
                    return Err(invalid());
                }
                read_source(&reader, r.claim, None)
            })
            .collect::<Result<Vec<_>>>()?;
        let voice = request
            .voice
            .iter()
            .map(|r| {
                if !seen.insert(r.claim) {
                    return Err(invalid());
                }
                read_source(&reader, r.claim, Some(request.owner))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(RepresentationContext {
            request: request.clone(),
            evidence,
            voice,
        })
    }
}
fn read_source(
    reader: &ScopedRead<'_>,
    id: EntityId,
    voice_owner: Option<EntityId>,
) -> Result<RepresentationSource> {
    let crate::claim::ScopedReadResult {
        value,
        receipt: _receipt,
    } = reader.get_entity_parts_with_receipt(&id, None)?;
    let (kind, _, bytes) = value.ok_or_else(invalid)?;
    if kind != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(invalid());
    }
    let body = decode_claim_body(&bytes, true)?;
    if !claim_evidence_admissible(&body) {
        return Err(invalid());
    }
    if let Some(owner) = voice_owner
        && (body.source != Some(ClaimSource::UserStated)
            || session_claim_producer(&body) != Some(owner))
    {
        return Err(invalid());
    }
    let text = body.value.as_str().ok_or_else(invalid)?;
    if text.trim().is_empty() || text.len() > 32_768 {
        return Err(invalid());
    }
    Ok(RepresentationSource {
        claim: id,
        revision: *blake3::hash(&bytes).as_bytes(),
        text: text.into(),
    })
}
pub(super) fn validate_citations(
    sources: &[RepresentationSource],
    citations: &[RepresentationCitation],
    text: Option<&str>,
) -> Result<()> {
    if citations.is_empty() || citations.len() > sources.len() {
        return Err(invalid());
    }
    let mut seen = BTreeSet::new();
    for citation in citations {
        let source = sources
            .iter()
            .find(|s| s.claim == citation.claim)
            .ok_or_else(invalid)?;
        if !seen.insert(citation.claim)
            || citation.revision != source.revision
            || citation.quote.trim().is_empty()
            || !source.text.contains(&citation.quote)
            || text.is_some_and(|text| !text.contains(&citation.marker()))
        {
            return Err(invalid());
        }
    }
    if let Some(text) = text {
        for suffix in text.split('[').skip(1) {
            let Some((label, _)) = suffix.split_once(']') else {
                continue;
            };
            if label.contains('@') && !citations.iter().any(|c| c.marker() == format!("[{label}]"))
            {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
pub(super) fn validate_packet(vault: &Vault, packet: &Packet) -> Result<()> {
    let context = vault.representation_context(&packet.request)?;
    let bytes = crate::compaction::output::restore_output(vault, packet.content)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    if text.trim().is_empty() || text.len() > 65_536 {
        return Err(invalid());
    }
    validate_citations(&context.evidence, &packet.evidence, Some(text))?;
    // Voice provenance belongs to the review artifact, not the external message.
    validate_citations(&context.voice, &packet.voice, None)
}
