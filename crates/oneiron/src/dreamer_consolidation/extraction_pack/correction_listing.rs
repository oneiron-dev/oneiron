//! The listing one lent correction read shows and its eligible pairs.
//!
//! The pairs and the listed claims are rebuilt from the bound projection as the native
//! correction read picks them, and each operand's cited claims are admitted by the bound
//! read's cited-head rule. Nothing here asks a model or writes a row.

use super::super::value_projection::rmpv_to_json;
use super::BoundBranchRead;
use super::reads::parse_reference;
use super::step_records::{OperandBound, takes_head_relationship};
use crate::entity_id::EntityId;
use crate::error::Result;
use crate::verbs::CandidateOperand;

/// One listed claim as the rebuild holds it: its id and subject with its
/// predicate and value as the listing writes them.
pub(super) struct CorrectionListed {
    /// The listed claim id.
    pub(super) claim: EntityId,
    /// The subject the listing shows it about.
    pub(super) subject: EntityId,
    /// The predicate as the listing writes it.
    pub(super) predicate: String,
    /// The value as JSON text, as the listing writes it.
    pub(super) value_text: String,
}

/// The eligible (candidate position, listed index) pairs over `operands` with
/// the listing in native first-seen order: every claim the bound listing
/// shows about each subject that its read may correct, except a claim the
/// candidate restates and a claim whose relationship set the candidate may
/// not take. Native never asks about a restated claim (FIX 8295), and a
/// claim left in no pair is not listed. `cited` holds each operand's
/// admitted claim evidence and `bounds` what the shared operand check fixed
/// for each operand, both by position. An operand that names recorded
/// candidates is paired only with a head one of them may be asked about.
///
/// A correcting candidate takes the relationship set of the head it
/// corrects, and assembly refuses a set outside the candidate's own
/// (S63E-RULED: a claim never holds wider than its words' label). A native
/// candidate that the model binds to such a head is not written. Here that
/// head is left in no pair, so no read asks about it and no request names it
/// in `corrects`: the candidate stands on its own proposal, inside its own
/// set.
pub(super) fn correction_sets(
    operands: &[CandidateOperand],
    subjects: &[EntityId],
    cited: &[Vec<EntityId>],
    (bound, bounds): (&BoundBranchRead, &[OperandBound]),
) -> Result<(Vec<(usize, usize)>, Vec<CorrectionListed>)> {
    let mut entries: Vec<(usize, usize)> = Vec::new();
    let mut listed: Vec<CorrectionListed> = Vec::new();
    let rows = operands.iter().zip(subjects).zip(cited);
    for (position, ((operand, subject), cited)) in rows.enumerate() {
        let fixed = bounds.get(position);
        let within = fixed.and_then(|fixed| fixed.relationship.as_ref());
        let askable = fixed.and_then(|fixed| fixed.askable.as_ref());
        for (claim, predicate, value) in bound.correctable(*subject, bound.scope()) {
            if cited.contains(&claim) && restates(operand, bound, claim) {
                continue;
            }
            if askable.is_some_and(|heads| !heads.contains(&claim)) {
                continue;
            }
            if !takes_head_relationship(bound, claim, within) {
                continue;
            }
            let at = match listed.iter().position(|row| row.claim == claim) {
                Some(at) => at,
                None => {
                    listed.push(CorrectionListed {
                        claim,
                        subject: *subject,
                        predicate,
                        value_text: value,
                    });
                    listed.len() - 1
                }
            };
            entries.push((position, at));
        }
    }
    Ok((entries, listed))
}

/// Whether `operand`, which cites listed `claim`, restates it unchanged: it
/// carries the head's own predicate and its value as JSON. The subject is the
/// head's, since the listing shows the head about that subject. This mirrors
/// the native correction read's restatement rule over the bound prior heads.
pub(super) fn restates(
    operand: &CandidateOperand,
    bound: &BoundBranchRead,
    claim: EntityId,
) -> bool {
    bound.prior(claim).is_some_and(|prior| {
        operand.predicate == prior.body.predicate
            && rmpv_to_json(&prior.body.value) == operand.value
    })
}

/// The listed heads `operand` cites as evidence, sorted and deduped: each
/// reference parsed canonically and each head admitted by the bound read's
/// cited-head rule, so a candidate never rests on a claim outside the
/// branch's listing or one that may not corroborate. Which call showed the
/// head is not checked: `BoundBranchRead::cited_head` says why.
pub(super) fn cited_claims(
    operand: &CandidateOperand,
    bound: &BoundBranchRead,
) -> Result<Vec<EntityId>> {
    let mut cited = operand
        .claim_evidence
        .iter()
        .map(|pin| parse_reference(&pin.claim))
        .collect::<Result<Vec<_>>>()?;
    cited.sort_unstable();
    cited.dedup();
    for claim in &cited {
        bound.cited_head(*claim)?;
    }
    Ok(cited)
}
