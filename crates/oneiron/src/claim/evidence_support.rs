//! Live support for typed derived claims, resolved in the caller's read snapshot.

use heed::RoTxn;
use rmpv::Value;

use crate::actor_claims::{actor_archive_references, is_actor_claim_predicate};
use crate::dreamer_consolidation::decode_consolidation_evidence;
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::store::ManifestDbs;
use crate::write_envelope::{
    WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY, WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY,
    envelope_carried_evidence,
};

use super::ClaimBody;

/// What one evidence slot of a claim asks of a read.
enum SlotSupport {
    /// The slot cites nothing by type, so it asks nothing.
    Unasked,
    /// One of `refs` must be live; with `turns_only`, a live TURN.
    Cited {
        refs: Vec<EntityId>,
        turns_only: bool,
    },
    /// A malformed typed slot, which cannot show support.
    Malformed,
}

/// Which rule a read applies to a cited CLAIM the owner retracted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum CitedSupport {
    /// Every serving read: a retracted cited claim supports nothing, so a
    /// claim derived only from it is not served (Engine ANSWER
    /// DERIVED-CLAIM-RETRACTED-SOURCE-SUPPORT = A).
    #[default]
    Served,
    /// The claim history door (`Memory::claim_history`): a retraction ends
    /// serving, not the record, so a retracted cited claim still counts
    /// while its row lives. Every other support rule applies as served.
    History,
}

/// A derived claim's live support on every serving read:
/// [`has_live_support_under_in_txn`] under [`CitedSupport::Served`].
pub(crate) fn has_live_support_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    body: &ClaimBody,
) -> Result<bool> {
    has_live_support_under_in_txn(store, txn, body, CitedSupport::Served)
}

/// A derived claim with typed TURN citations is readable while at least one
/// cited turn remains live. Under [`CitedSupport::Served`] a cited CLAIM the
/// owner retracted is not live (`retracted_claim`); a superseded one is.
/// Under [`CitedSupport::History`] a retracted one counts. This is a
/// read-time test: sync can deliver a claim after the deletion that erased
/// its source, or before the retraction of the claim it cites. Ordinary
/// claims have no such evidence obligation, and claim history remains
/// available through get_claim.
/// A stamped successor of a raw claim keeps that claim's obligation: the
/// evidence it carries is read as the raw claim's own. A stamped claim's
/// writer evidence (`candidate_evidence`, where the Dreamer's promotion and a
/// derive item put their consolidation envelope) cites as a raw claim's own
/// envelope does. Every citing slot asks together: one live cited row among
/// them supports the claim, and one malformed slot fails it. `store` is the
/// content read: a room's view finds a turn the room holds.
pub(crate) fn has_live_support_under_in_txn(
    store: &impl ManifestDbs,
    txn: &RoTxn<'_>,
    body: &ClaimBody,
    rule: CitedSupport,
) -> Result<bool> {
    let mut slots = vec![written_support(body)];
    if let Some(candidate) = body.evidence.as_ref().and_then(stamped_candidate_evidence) {
        slots.push(candidate_support(candidate));
    }
    let mut cited = Vec::new();
    for slot in slots {
        match slot {
            SlotSupport::Unasked => {}
            SlotSupport::Malformed => return Ok(false),
            SlotSupport::Cited { refs, turns_only } => cited.push((refs, turns_only)),
        }
    }
    if cited.is_empty() {
        return Ok(true);
    }
    for (refs, turns_only) in cited {
        for id in refs {
            if let crate::vault::LiveEntityRow::Live {
                entity_type,
                body: row,
            } = crate::vault::live_entity_row_in_txn(store, txn, &id)?
                && (!turns_only || entity_type == crate::registry::ENTITY_TYPE_TURN)
                && (rule == CitedSupport::History || !retracted_claim(entity_type, &row))
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// What a claim's evidence asks where it was written: a raw body's own
/// evidence, or the raw predecessor's evidence a stamped successor carries.
fn written_support(body: &ClaimBody) -> SlotSupport {
    let carried;
    let body = match body.evidence.as_ref().and_then(envelope_carried_evidence) {
        Some(evidence) => {
            carried = ClaimBody {
                evidence: Some(evidence.clone()),
                ..body.clone()
            };
            &carried
        }
        None => body,
    };
    if is_actor_claim_predicate(&body.predicate) {
        let chat_lane = body
            .evidence
            .as_ref()
            .and_then(Value::as_map)
            .is_some_and(|entries| {
                entries.iter().any(|(key, value)| {
                    key.as_str() == Some("lane") && value.as_str() == Some("chat")
                })
            });
        if !chat_lane {
            return SlotSupport::Unasked;
        }
        // The canonical actor codec, not matching map keys alone, determines
        // which refs are evidence. A malformed CHAT row cannot claim support.
        let Some(Some((_, turns))) = actor_archive_references(body).map(|refs| refs.chat) else {
            return SlotSupport::Malformed;
        };
        return SlotSupport::Cited {
            refs: turns,
            turns_only: true,
        };
    }
    let Some(evidence) = &body.evidence else {
        return SlotSupport::Unasked;
    };
    match decode_consolidation_evidence(evidence) {
        Ok(Some(envelope)) => SlotSupport::Cited {
            refs: envelope.refs,
            turns_only: false,
        },
        // A partially keyed consolidation envelope is not an ordinary
        // opaque evidence map with no support obligation.
        Ok(None) if holds_envelope_key(evidence) => SlotSupport::Malformed,
        Ok(None) => SlotSupport::Unasked,
        Err(_) => SlotSupport::Malformed,
    }
}

/// Whether `evidence` holds any key of a consolidation envelope.
fn holds_envelope_key(evidence: &Value) -> bool {
    evidence.as_map().is_some_and(|fields| {
        fields
            .iter()
            .any(|(key, _)| matches!(key.as_str(), Some("refs" | "chain" | "source_meet")))
    })
}

/// A stamped claim's writer evidence: the `candidate_evidence` entry of a
/// write-envelope stamp. A raw body has none.
fn stamped_candidate_evidence(evidence: &Value) -> Option<&Value> {
    let entries = evidence.as_map()?;
    let field = |name: &str| {
        entries
            .iter()
            .find(|(key, _)| key.as_str() == Some(name))
            .map(|(_, value)| value)
    };
    field(WRITE_ENVELOPE_EVIDENCE_ACTOR_KEY)?;
    field(WRITE_ENVELOPE_EVIDENCE_CANDIDATE_KEY)
}

/// Whether `evidence` is keyed as a consolidation envelope: it holds both
/// `refs` and `chain`, as the envelope encoder always writes them.
fn keyed_as_envelope(evidence: &Value) -> bool {
    evidence.as_map().is_some_and(|fields| {
        ["refs", "chain"]
            .iter()
            .all(|name| fields.iter().any(|(key, _)| key.as_str() == Some(*name)))
    })
}

/// What a stamped claim's writer evidence asks. A consolidation envelope that
/// cites rows asks for one of them, as the write gate's reference read and
/// the source recheck read this slot. A map without both `refs` and `chain`
/// is no envelope and asks nothing, whatever its `refs` hold: the engine's
/// bare `refs` lists (a supersession provenance claim, its conflict-open
/// claim, a nightly merge) and a caller's own evidence that names `refs`.
/// An envelope that cites no row asks nothing; a malformed envelope cannot
/// show support.
fn candidate_support(evidence: &Value) -> SlotSupport {
    if !keyed_as_envelope(evidence) {
        return SlotSupport::Unasked;
    }
    match decode_consolidation_evidence(evidence) {
        Ok(Some(envelope)) if !envelope.refs.is_empty() => SlotSupport::Cited {
            refs: envelope.refs,
            turns_only: false,
        },
        Ok(_) => SlotSupport::Unasked,
        Err(_) => SlotSupport::Malformed,
    }
}

/// Whether a live row of `entity_type` holding `body` is a retracted CLAIM,
/// which supports nothing: a retraction says the claim was wrong (Engine
/// ANSWER DERIVED-CLAIM-RETRACTED-SOURCE-SUPPORT = A; canon ARCH-0004
/// hydration). A superseded claim still supports, because a newer version
/// replaced it and no one refuted it. A body that does not decode is read as
/// before this rule, by its row alone.
fn retracted_claim(entity_type: u8, body: &[u8]) -> bool {
    entity_type == crate::registry::ENTITY_TYPE_CLAIM
        && super::decode_claim_body(body, true)
            .is_ok_and(|claim| claim.lifecycle == super::ClaimLifecycleStatus::Retracted)
}
