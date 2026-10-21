//! A weave report's Admissions section reads the loop decisions (OF-499
//! A2): the gate decisions a Dreamer or Coach loop, a resident's dreaming
//! or a turn program left, admitted and refused alike, each one the reader
//! may see through the authorised loop-decision read. They follow the
//! section's predicate rows in that read's ledger order, none dropped,
//! merged or re-sorted. A row is its event's own metadata and refs, never a
//! hydrated body, and its dependencies are evidence refs only.
use super::super::loop_decision_read::ReadableLoopDecision;
use super::super::{ScopedRead, WeaveItemView};
use super::{WeaveItem, WeaveReader};
use crate::EntityId;
use crate::error::{Error, Result};

impl ScopedRead<'_> {
    /// Every loop decision `reader` may see in `txn`, as Admissions rows in
    /// ledger order. The read admits each event before any field and each
    /// ref under its own floor; a pending decision keeps its own outcome,
    /// and a skeleton its empty reasons and absent actor. Nothing here
    /// refuses or fails the report: a read that does not bind adds no row.
    pub(super) fn weave_loop_decisions_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: WeaveReader<'_>,
    ) -> Vec<WeaveItem> {
        self.readable_loop_decisions_in_txn(txn, reader)
            .into_iter()
            .map(loop_decision_item)
            .collect()
    }

    /// The authorised loop-decision read for `reader`, through the one
    /// hook that names its reader ([`loop_decision_reader`]). A live report
    /// and a saved period's recheck both read here.
    pub(crate) fn readable_loop_decisions_in_txn(
        &self,
        txn: &heed::RoTxn<'_>,
        reader: WeaveReader<'_>,
    ) -> Vec<ReadableLoopDecision> {
        self.authorised_loop_decisions_in_txn(txn, loop_decision_reader(reader))
    }
}

/// The hook that names the reader a weave's loop-decision read binds (FIX
/// 7572). Every reader passes as it is: the read is the authority, and it
/// returns only what that reader may see (nothing on a failed bind or a
/// lane that reads no row). An agent's own-Grant alternative (OF-499 A3)
/// lands inside that read under the same signature, so it reaches agents
/// with no change here. Whether a reader has an Admissions section at all
/// stays its weave policy's call. The match is exhaustive so that a new
/// reader role decides here.
fn loop_decision_reader(reader: WeaveReader<'_>) -> WeaveReader<'_> {
    match reader {
        WeaveReader::Owner(_) | WeaveReader::Person(_) | WeaveReader::Agent(_) => reader,
    }
}

/// One authorised decision as its report row: each field copied once, the
/// family by its served name, the dependencies as evidence refs.
pub(crate) fn loop_decision_item(decision: ReadableLoopDecision) -> WeaveItem {
    WeaveItem::LoopDecision {
        decision_id: decision.decision_id,
        created_at: decision.created_at,
        family: decision.family.name().to_owned(),
        kind: decision.kind,
        outcome: decision.outcome,
        reason_codes: decision.reason_codes,
        redacted: decision.redacted,
        claim_ref: decision.claim_ref,
        actor_ref: decision.actor_ref,
        evidence_refs: decision.dependencies,
    }
}

/// A loop decision row as a report serves it: its refs as hex, nothing
/// hydrated. Any other row is not this view's.
pub(crate) fn loop_decision_view(item: &WeaveItem) -> Result<WeaveItemView> {
    let WeaveItem::LoopDecision {
        decision_id,
        created_at,
        family,
        kind,
        outcome,
        reason_codes,
        redacted,
        claim_ref,
        actor_ref,
        evidence_refs,
    } = item
    else {
        return Err(Error::InvalidConfig(
            "a weave row is not a loop decision".into(),
        ));
    };
    Ok(WeaveItemView::LoopDecision {
        decision_ref: decision_id.to_hex(),
        created_at: *created_at,
        family: family.clone(),
        kind: kind.clone(),
        outcome: outcome.clone(),
        reason_codes: reason_codes.clone(),
        redacted: *redacted,
        claim_ref: claim_ref.map(|id| id.to_hex()),
        actor_ref: actor_ref.map(|id| id.to_hex()),
        evidence_refs: evidence_refs.iter().map(EntityId::to_hex).collect(),
    })
}
