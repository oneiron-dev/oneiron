//! Actor-scoped evidence and owner-authored voice reads, with exact revision pins.
use super::{Packet, RepresentationCitation, RepresentationRequest, invalid};
use crate::claim::{
    PointRead, ReadRow, ScopedRead, ScopedReadActorKey, ScopedReadReceipt, ScopedReadResult,
    claim_evidence_admissible, decode_claim_body, session_claim_producer,
};
use crate::settings::{ReadDestination, ReleaseHold};
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
    /// The Dreamer actor's read of every evidence and voice source, folded.
    pub receipt: ScopedReadReceipt,
}
/// What one model destination may receive of a request's sources (FIX 8714).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationContext {
    /// The sources `destination` may receive, the request narrowed to them,
    /// with the receipt of the read bound to that destination.
    pub context: RepresentationContext,
    /// Where they go: the actual destination of the model call.
    pub destination: ReadDestination,
    /// Why the first source left out was, when one was.
    pub held: Option<ReleaseHold>,
}
impl Vault {
    /// The model host receives only these admitted source texts. Claim bytes
    /// and owner voice are never read through an unscoped fallback, and a
    /// relationship's rows need the Dreamer's live AccessGrant.
    pub fn representation_context(
        &self,
        request: &RepresentationRequest,
    ) -> Result<RepresentationContext> {
        if request.evidence.is_empty()
            || request.voice.is_empty()
            || [&request.verb, &request.channel, &request.target]
                .into_iter()
                .any(|s| s.trim().is_empty() || s.chars().any(char::is_control))
        {
            return Err(invalid());
        }
        crate::outbound::outbound_verb_contract(&request.channel, &request.verb)
            .map_err(|_| invalid())?;
        let actor = self.dreamer_authority()?.entity_ref();
        // Relationship and private rows pass only on the Dreamer's own live
        // grants, as consolidation's message reader reads them.
        let reader = self.scoped_read(
            ScopedReadActorKey::with_actor_class(actor.to_hex(), "system")
                .ok_or_else(invalid)?
                .require_relationship_grants(Some(actor)),
        );
        let mut seen = BTreeSet::new();
        let mut receipt = reader.read_receipt(None, 0)?;
        let mut read = |id: EntityId, voice_owner: Option<EntityId>| {
            if !seen.insert(id) {
                return Err(invalid());
            }
            let source = read_source(&reader, id, voice_owner)?;
            receipt.restrict_with(&source.receipt);
            Ok(source.value)
        };
        let evidence = request
            .evidence
            .iter()
            .map(|r| read(r.claim, None))
            .collect::<Result<Vec<_>>>()?;
        let voice = request
            .voice
            .iter()
            .map(|r| read(r.claim, Some(request.owner)))
            .collect::<Result<Vec<_>>>()?;
        Ok(RepresentationContext {
            request: request.clone(),
            evidence,
            voice,
            receipt,
        })
    }

    /// What `destination`, where a model call actually goes, may receive of
    /// `request`'s sources (FIX 8714). Each evidence and voice source is read
    /// first as [`Self::representation_context`] reads it, which refuses as
    /// it does; then again by the Dreamer's reader bound to `destination`,
    /// and only while the world settings let its world go there as a model
    /// call. A source either withholds is left out, the request narrowed to
    /// the rest; one whose bytes moved between the reads is left out too.
    pub fn representation_context_for(
        &self,
        request: &RepresentationRequest,
        destination: &ReadDestination,
    ) -> Result<DestinationContext> {
        let local = self.representation_context(request)?;
        let actor = self.dreamer_authority()?.entity_ref();
        let reader = self.scoped_read(
            ScopedReadActorKey::with_actor_class(actor.to_hex(), "system")
                .ok_or_else(invalid)?
                .require_relationship_grants(Some(actor))
                .for_destination(destination),
        );
        let mut receipt = reader.read_receipt(None, 0)?;
        let mut held = None;
        let mut admit = |sources: Vec<RepresentationSource>| {
            let mut kept = Vec::with_capacity(sources.len());
            for source in sources {
                match destination_read(self, &reader, &source, destination)? {
                    Ok(read) => {
                        receipt.restrict_with(&read);
                        kept.push(source);
                    }
                    Err(hold) => {
                        held.get_or_insert(hold);
                    }
                }
            }
            Ok::<_, crate::Error>(kept)
        };
        let evidence = admit(local.evidence)?;
        let voice = admit(local.voice)?;
        let mut request = local.request;
        request
            .evidence
            .retain(|r| evidence.iter().any(|source| source.claim == r.claim));
        request
            .voice
            .retain(|r| voice.iter().any(|source| source.claim == r.claim));
        Ok(DestinationContext {
            context: RepresentationContext {
                request,
                evidence,
                voice,
                receipt,
            },
            destination: destination.clone(),
            held,
        })
    }
}

/// `source`, read again by `reader`, bound to `destination`: its receipt
/// while the same bytes read there and the world settings let its world go
/// to `destination` as a model call (`Vault::model_call_hold_for`, the judge
/// a model offer's own world hold reads); else why not.
fn destination_read(
    vault: &Vault,
    reader: &ScopedRead<'_>,
    source: &RepresentationSource,
    destination: &ReadDestination,
) -> Result<std::result::Result<ScopedReadReceipt, ReleaseHold>> {
    let ScopedReadResult { value, receipt } =
        reader.read(&[PointRead::id(source.claim)], None)?.single();
    let Some(ReadRow {
        body: Some(bytes), ..
    }) = value
    else {
        let hold = vault.release_hold_for(&[source.claim], destination)?;
        return Ok(Err(hold.unwrap_or(ReleaseHold::Placement)));
    };
    if *blake3::hash(&bytes).as_bytes() != source.revision {
        return Ok(Err(ReleaseHold::Placement));
    }
    let world = decode_claim_body(&bytes, true)?
        .world
        .unwrap_or_else(crate::claim::base_world_id);
    Ok(match vault.model_call_hold_for(Some(world), destination)? {
        Some(hold) => Err(hold),
        None => Ok(receipt),
    })
}
fn read_source(
    reader: &ScopedRead<'_>,
    id: EntityId,
    voice_owner: Option<EntityId>,
) -> Result<ScopedReadResult<RepresentationSource>> {
    let ScopedReadResult { value, receipt } = reader.read(&[PointRead::id(id)], None)?.single();
    let Some(ReadRow {
        entity_type: kind,
        body: Some(bytes),
        ..
    }) = value
    else {
        return Err(invalid());
    };
    if kind != crate::registry::ENTITY_TYPE_CLAIM {
        return Err(invalid());
    }
    let body = decode_claim_body(&bytes, true)?;
    // A source awaiting its owner's answer is a missing required source.
    if !claim_evidence_admissible(&body)
        || !reader.vault().claim_consolidation_eligible(
            &id,
            crate::gate::ConsolidationReader::RepresentationSource,
        )?
    {
        return Err(invalid());
    }
    if let Some(owner) = voice_owner
        && (body.source != Some(ClaimSource::UserStated)
            || session_claim_producer(&body) != Some(owner))
    {
        return Err(invalid());
    }
    let text = body.value.as_str().ok_or_else(invalid)?;
    if text.trim().is_empty() {
        return Err(invalid());
    }
    Ok(ScopedReadResult {
        value: RepresentationSource {
            claim: id,
            revision: *blake3::hash(&bytes).as_bytes(),
            text: text.into(),
        },
        receipt,
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
/// Rechecks `packet` for `owner`, the live person its envelope names: the
/// packet itself names no one (FIX 4512).
pub(super) fn validate_packet(vault: &Vault, packet: &Packet, owner: EntityId) -> Result<()> {
    // A follow-up stands only while its reach-out does: one the owner
    // reverted or declined, or one rewritten since, refuses it everywhere.
    if let Some(pin) = &packet.reach_out
        && !reach_out_stands(vault, pin.claim, pin.revision)?
    {
        return Err(invalid());
    }
    let context = vault.representation_context(&packet.request.with_owner(owner))?;
    let bytes = crate::compaction::output::restore_output(vault, packet.content)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid())?;
    if text.trim().is_empty() {
        return Err(invalid());
    }
    validate_citations(&context.evidence, &packet.evidence, Some(text))?;
    // Voice provenance belongs to the review artifact, not the external message.
    validate_citations(&context.voice, &packet.voice, None)
}

/// Whether the reach-out `claim` still stands at `revision`.
pub(super) fn reach_out_stands(vault: &Vault, claim: EntityId, revision: [u8; 32]) -> Result<bool> {
    let authority = vault.dreamer_authority()?.entity_ref();
    let txn = vault.store.env.read_txn()?;
    reach_out_stands_in_txn(vault, &txn, authority, claim, revision)
}

/// [`reach_out_stands`] in the caller's snapshot, for the Dreamer `authority`.
pub(super) fn reach_out_stands_in_txn(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    authority: EntityId,
    claim: EntityId,
    revision: [u8; 32],
) -> Result<bool> {
    Ok(
        super::super::stewardship::standing_reach_out_in_txn(vault, txn, authority, claim)?
            .is_some_and(|(_, standing)| standing == revision),
    )
}
