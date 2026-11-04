//! Edge provenance precedence and pure record lifecycle values.

use super::codec::derive_confirmation_status;
use super::{EdgeProvenanceClaimBody, EdgeRef, SupersessionStatus};
use crate::write_envelope::claim_body::ClaimBody;
use oneiron_base::edge::{EdgeActorClass, EdgeProvenanceFlags};
use oneiron_contracts::entity_id::EntityId;
use oneiron_contracts::error::{ClaimError, Error, Result};

/// D14 precedence key of one live provenance Claim, used to pick the
/// deterministic flag-stamp WINNER.
#[derive(Debug, Clone, Copy)]
pub struct ProvenancePrecedence {
    /// The Claim ENTITY's envelope `learned_at` (D14: "later
    /// source_revision_ref" = envelope learned_at; the ref is opaque).
    pub learned_at: u64,
    /// The record's `confidence` — breaks `learned_at` ties.
    pub confidence: f32,
    /// Final engine-defined tiebreak: greatest claim-id bytes win, making
    /// the order total and the winner deterministic.
    pub claim_id: EntityId,
}

/// Returns the index of the WINNER among live provenance Claims under the
/// documented total D14 order: greatest `learned_at`, then greatest
/// `confidence` (`f32::total_cmp` — confidence is validated finite in
/// `[0, 1]`), then greatest claim-id bytes. `None` for an empty slate.
pub fn winner_index(candidates: &[ProvenancePrecedence]) -> Option<usize> {
    candidates
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| {
            a.learned_at
                .cmp(&b.learned_at)
                .then_with(|| a.confidence.total_cmp(&b.confidence))
                .then_with(|| a.claim_id.as_bytes().cmp(b.claim_id.as_bytes()))
        })
        .map(|(index, _)| index)
}

/// Closes a value record for SUPERSESSION: `valid_to` is set to `close_at`
/// ONLY when the record had no `valid_to` of its own — an explicit,
/// already-closed validity window is preserved, never extended. The
/// `supersession_status` is untouched (the enum has no "superseded" state;
/// closure lives in the wrapper's `life` + the validity window). Fails typed
/// when the effective window would be inverted.
pub fn close_record_for_supersession(
    record: &EdgeProvenanceClaimBody,
    close_at: u64,
) -> Result<EdgeProvenanceClaimBody> {
    let mut closed = record.clone();
    if closed.valid_to.is_none() {
        closed.valid_to = Some(close_at);
    }
    ensure_record_window(&closed)?;
    Ok(closed)
}

/// Applies the contract's RETRACT rule to a value record:
/// `supersession_status` = retracted and `valid_to` = `now` (the literal
/// "set supersession_status = retracted (and typically valid_to = now)" —
/// retraction is a deliberate withdrawal AT `now`, so an explicit prior
/// `valid_to` is overwritten). Fails typed when `valid_from` exceeds `now`.
pub fn retract_record(
    record: &EdgeProvenanceClaimBody,
    now: u64,
) -> Result<EdgeProvenanceClaimBody> {
    let mut retracted = record.clone();
    retracted.supersession_status = SupersessionStatus::Retracted;
    retracted.valid_to = Some(now);
    ensure_record_window(&retracted)?;
    Ok(retracted)
}

fn ensure_record_window(record: &EdgeProvenanceClaimBody) -> Result<()> {
    if let (Some(from), Some(to)) = (record.valid_from, record.valid_to)
        && from > to
    {
        return Err(Error::Claim(ClaimError::InvalidProvenanceBody(
            "closing valid_to precedes valid_from",
        )));
    }
    Ok(())
}

/// One stored `edge.provenance` Claim loaded for a lifecycle operation
/// (retract / supersede / winner refresh).
pub struct StoredProvenanceClaim {
    pub id: EntityId,
    /// Envelope `occurred.start`, preserved verbatim on closing re-puts.
    pub occurred_start: u64,
    /// Envelope `learned_at` — the D14 precedence key. NEVER changed by a
    /// lifecycle re-put.
    pub learned_at: u64,
    /// The 33-byte EdgeRef the Claim addresses (from its `subj`).
    pub subject: EdgeRef,
    /// The wrapping type-0 Claim body.
    pub wrapper: ClaimBody,
    /// The decoded 10-key `edge.provenance` value record (ONE-1138).
    pub record: EdgeProvenanceClaimBody,
    /// The write-time validated actor class, resolved from the record's
    /// `actor_class` body key (new shape) or the wrapper's legacy `evid`
    /// map (pre-ONE-1138 claims) — see the provenance module docs.
    pub actor_class: EdgeActorClass,
}

impl StoredProvenanceClaim {
    /// This Claim's D14 precedence key.
    pub fn precedence(&self) -> ProvenancePrecedence {
        ProvenancePrecedence {
            learned_at: self.learned_at,
            confidence: self.record.confidence,
            claim_id: self.id,
        }
    }

    /// The edge flags this Claim derives (contracts.ts `derivesEdgeFlags`):
    /// `confirmation_status` ← `supersession_status` identity mirror;
    /// `actor_class` ← the persisted write-time validated class.
    pub fn flags(&self) -> EdgeProvenanceFlags {
        EdgeProvenanceFlags {
            confirmation_status: derive_confirmation_status(self.record.supersession_status),
            actor_class: self.actor_class,
        }
    }
}
