//! The candidate item: one extraction candidate that replaces nothing.
//!
//! Its operand is the bound verdict's operand, with the confidence and the
//! prospective query hints the claim lands with. Only a queued extraction
//! attempt stages one, as the attempt's Dreamer.
//!
//! Staging rebuilds the verdict's read in the batch's write transaction and
//! hands the one candidate to native's promotion writer. In order: the
//! attempt rule, the attempt's Dreamer, the verdict's operand checks, the
//! duplicate refusal, the unequal kept-match refusal, one verified member,
//! native's attachment-head rule over the equal matches, the unlisted
//! restatement refusal, the declined-words refusal, the derive verdict over
//! the subject, then in a savepoint either native's own preparation and
//! landing or the attachment to the equal head, with derive provenance and
//! no answers. A refusal lands nothing, writes the item's receipt, and the
//! batch goes on; a storage error aborts the commit.

use super::attachment_head::{AttachmentHead, attachment_head};
use super::batch::DerivedCandidate;
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn};
use super::conflict::inputs::{derive_provenance, member_candidate};
use super::extraction_opening::{open_attempt, open_verdict_read};
use super::verified_landing::{
    LandingError, LandingRefusal, VerifiedAttachment, VerifiedLandingOptions,
    attach_verified_candidate, attempt_dreamer_matches, land_verified_candidate, promotion_run_id,
    refuse, refuse_or_abort,
};
use crate::Vault;
use crate::dreamer_consolidation::extraction_pack::{
    ExtractionRebuildContext, check_extraction_operands_in_txn, check_pack_candidates,
    kept_matches_for_one_proposal,
};
use crate::error::{Error, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};

/// The refusal of a candidate item whose commit runs outside a queued
/// extraction attempt: it names no attempt, or its attempt is not in the
/// queue as a Micro, Meso or Macro consolidation attempt with a partition
/// payload.
pub const CANDIDATE_NEEDS_EXTRACTION_ATTEMPT: &str =
    "gate.deny.derive.candidate_needs_extraction_attempt";

/// The refusal of a candidate item whose stamp's actor is not the
/// attempt's Dreamer.
pub const CANDIDATE_NOT_ATTEMPT_DREAMER: &str = "gate.deny.derive.candidate_not_attempt_dreamer";

/// The refusal of a candidate item whose operand is not one servable
/// native candidate: a row the extraction read does not serve this actor,
/// an operand the native checks refuse, or a check the seal refuses.
pub const CANDIDATE_OPERAND_REFUSED: &str = "gate.deny.derive.candidate_operand_refused";

/// The refusal of an equal restatement native cannot attach to, or an
/// unlisted restatement.
pub const CANDIDATE_RESTATES_HEAD: &str = "gate.deny.derive.candidate_restates_head";

/// The refusal of a candidate item that contests a head: a kept match is
/// value-unequal, or the operand names a listed claim it corrects.
pub const CANDIDATE_CONTESTS_HEAD: &str = "gate.deny.derive.candidate_contests_head";

/// The refusal of a candidate item whose words the owner declined from the
/// same imported words.
pub const CANDIDATE_OWNER_DECLINED: &str = "gate.deny.derive.candidate_owner_declined";

/// The refusal of a candidate item whose claim is already stored: a row
/// stands at the candidate's claim id.
pub const CANDIDATE_DUPLICATE: &str = "gate.deny.derive.candidate_duplicate";

/// The refusal of a candidate item whose evidence meets at `Imported`: a
/// claim from imported evidence lands only in the owner's review of its
/// import; an unbound derive row has no review to join and an attachment
/// creates no claim that review could hold.
pub const CANDIDATE_IMPORTED_EVIDENCE: &str = "gate.deny.derive.candidate_imported_evidence";

/// The refusal of a candidate item native's promotion refused to land.
pub const CANDIDATE_LANDING_REFUSED: &str = "gate.deny.derive.candidate_landing_refused";

/// The reason a landed candidate item's receipt names.
const CANDIDATE_ALLOWED: &str = "gate.allow.derive.candidate";

/// The allowance for support attached to a standing head, without a new claim.
const CANDIDATE_ATTACHED: &str = "gate.allow.derive.candidate_attached";

/// Stages a candidate item: one extraction candidate that replaces
/// nothing, landed by native's writer inside the batch's write transaction
/// (`txn` reborrowed as a read for every read). Outside a queued
/// extraction attempt, or for any actor but the attempt's Dreamer, the item
/// is refused; inside one its operand and member are checked, then it
/// attaches to an equal head or lands one claim with derive provenance.
/// Each refusal writes the item's receipt and lands nothing, and the batch
/// goes on.
///
/// # Errors
///
/// Storage errors, and an attempt whose authority stamp no longer
/// validates: each aborts the whole commit, never a refusal.
pub(super) fn stage_in_txn(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    item: &DerivedCandidate,
) -> Result<ItemOutcome> {
    let Some(attempt_id) = open_attempt(vault, txn, context.stamp)? else {
        return refuse(
            vault,
            txn,
            context,
            &[CANDIDATE_NEEDS_EXTRACTION_ATTEMPT.to_owned()],
        );
    };
    // Native's rule for a promotion's run: its actor is the base agent the
    // attempt was stamped with, read here on this transaction.
    if !attempt_dreamer_matches(vault, txn, attempt_id, context.stamp.actor)? {
        return refuse(
            vault,
            txn,
            context,
            &[CANDIDATE_NOT_ATTEMPT_DREAMER.to_owned()],
        );
    }
    let opening = match open_verdict_read(vault, txn, context.stamp) {
        Ok(Some(opening)) => opening,
        Ok(None) => return refuse(vault, txn, context, &[CANDIDATE_OPERAND_REFUSED.to_owned()]),
        Err(error) => {
            return refuse_or_abort(vault, txn, context, error, CANDIDATE_OPERAND_REFUSED);
        }
    };
    let actor = opening.actor;
    let read = &opening.read;
    let turn_read = opening.turn_read();
    let memory = &opening.memory;
    // The verdict's operand checks over the one operand, with no claim pin:
    // the item names no head.
    let operands = std::slice::from_ref(&item.member.operand);
    let (branch, bound) = {
        let read_txn: &heed::RoTxn<'_> = txn;
        match check_extraction_operands_in_txn(
            memory,
            read,
            read_txn,
            opening.reader_scope.as_ref(),
            attempt_id,
            operands,
            None,
        ) {
            Ok(checked) => checked,
            Err(error) => {
                return refuse_or_abort(vault, txn, context, error, CANDIDATE_OPERAND_REFUSED);
            }
        }
    };
    let checked = match check_pack_candidates(operands, &bound, attempt_id, &branch) {
        Ok(checked) => checked,
        // A claim-domain failure of the operand is the request's, as the
        // Conflict stager reads it; anything else is the store's.
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return refuse(vault, txn, context, &[CANDIDATE_OPERAND_REFUSED.to_owned()]);
        }
        Err(error) => return Err(error),
    };
    let Some(proposal) = checked.rows.first().map(|row| &row.proposal) else {
        return refuse(vault, txn, context, &[CANDIDATE_OPERAND_REFUSED.to_owned()]);
    };
    // A candidate that corrects a listed claim replaces it: a set-level
    // item's, never this one's.
    if item.member.operand.corrects.is_some() {
        return refuse(vault, txn, context, &[CANDIDATE_CONTESTS_HEAD.to_owned()]);
    }
    // A row already stored at the candidate's id refuses the item, before
    // any head is matched: a branch lists the claim an earlier batch of its
    // own attempt landed, and that is this candidate met again, not a head
    // it restates. This replaces native's two guards for an attempt that
    // meets its own output again (its review-held output and its replay
    // after a kill): a batch commits once.
    let claim_id = proposal.claim_id;
    {
        let read_txn: &heed::RoTxn<'_> = txn;
        if vault.get_claim_in_txn(read_txn, &claim_id)?.is_some() {
            return refuse(vault, txn, context, &[CANDIDATE_DUPLICATE.to_owned()]);
        }
    }
    // The heads the candidate stands against after the observed-beside
    // exclusion, by the bound route's own rule. An unequal head refuses
    // the item; equal heads proceed to native's attachment rule.
    let kept = {
        let read_txn: &heed::RoTxn<'_> = txn;
        let rebuild = ExtractionRebuildContext {
            memory,
            read,
            turn_read,
            txn: read_txn,
            operands,
        };
        match kept_matches_for_one_proposal(&bound, &rebuild, proposal) {
            Ok(kept) => kept,
            Err(error) => {
                return refuse_or_abort(vault, txn, context, error, CANDIDATE_OPERAND_REFUSED);
            }
        }
    };
    if kept.iter().any(|(_, equal)| !equal) {
        return refuse(vault, txn, context, &[CANDIDATE_CONTESTS_HEAD.to_owned()]);
    }
    // The member: the checked proposal stamped with the item's confidence
    // and normalised hints, then verified as native verifies it at the
    // commit's clock. Neither enters the id law, so the claim id stands.
    let now_ms = context.now.saturating_mul(1_000);
    let mut stamped = proposal.clone();
    stamped.candidate = member_candidate(
        &proposal.candidate,
        item.member.confidence,
        &item.member.prospective_queries,
    )?;
    let verified = {
        let read_txn: &heed::RoTxn<'_> = txn;
        match bound.verify_observation_candidate_in_txn(
            memory,
            turn_read,
            read_txn,
            &item.member.operand,
            &stamped,
            now_ms,
        ) {
            Ok(verified) => verified,
            Err(error) => {
                return refuse_or_abort(vault, txn, context, error, CANDIDATE_OPERAND_REFUSED);
            }
        }
    };
    let evidence = verified.evidence;
    let mut candidate = verified.proposal;
    candidate.evidence_meet = evidence.meet();
    let attachment = match attachment_head(&bound, &candidate, &kept, evidence.meet()) {
        Ok(AttachmentHead::Attach(head)) => Some(head),
        Ok(AttachmentHead::AlreadySaid) => {
            return refuse(vault, txn, context, &[CANDIDATE_RESTATES_HEAD.to_owned()]);
        }
        Ok(AttachmentHead::NoHead) if kept.is_empty() => None,
        Ok(AttachmentHead::NoHead) => {
            return refuse(vault, txn, context, &[CANDIDATE_RESTATES_HEAD.to_owned()]);
        }
        Ok(AttachmentHead::Refused) | Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return refuse(vault, txn, context, &[CANDIDATE_OPERAND_REFUSED.to_owned()]);
        }
        Err(error) => return Err(error),
    };
    // Native's two skips for a candidate that matched no listed head: an
    // unlisted head of the Dreamer's own that says the same, and words the
    // owner declined from the same imported MESSAGEs.
    {
        let read_txn: &heed::RoTxn<'_> = txn;
        if attachment.is_none() {
            match bound.restates_unlisted_candidate_in_txn(
                vault,
                read,
                read_txn,
                &candidate,
                candidate.evidence_meet,
            ) {
                Ok(true) => {
                    return refuse(vault, txn, context, &[CANDIDATE_RESTATES_HEAD.to_owned()]);
                }
                Ok(false) => {}
                Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                    return refuse(vault, txn, context, &[CANDIDATE_OPERAND_REFUSED.to_owned()]);
                }
                Err(error) => return Err(error),
            }
        }
        match crate::dreamer_consolidation::reviewed::declined_from_same_words_in_txn(
            vault,
            read_txn,
            &candidate,
            &evidence.cited_messages(),
        ) {
            Ok(Some(_)) => {
                return refuse(vault, txn, context, &[CANDIDATE_OWNER_DECLINED.to_owned()]);
            }
            Ok(None) => {}
            Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
                return refuse(vault, txn, context, &[CANDIDATE_OPERAND_REFUSED.to_owned()]);
            }
            Err(error) => return Err(error),
        }
    }
    // The derive verdict over the candidate's subject, as the Conflict
    // stager takes it. An attachment asserts the same entity subject as
    // its matched head; the claim gate separately keeps the head's full scope.
    let subject = match crate::dreamer_consolidation::candidate_probe_body(&candidate.candidate) {
        Ok(body) => match body.subject {
            crate::claim::ClaimSubject::Entity(subject) => subject,
            _ => return refuse(vault, txn, context, &[CANDIDATE_OPERAND_REFUSED.to_owned()]),
        },
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            return refuse(vault, txn, context, &[CANDIDATE_OPERAND_REFUSED.to_owned()]);
        }
        Err(error) => return Err(error),
    };
    let allowance = match derive_verdict_in_txn(
        &vault.store,
        txn,
        actor,
        DeriveCapability::Derive,
        Some(subject),
    )? {
        Ok(allowance) => allowance,
        Err(refusal) => return refuse(vault, txn, context, &[refusal.token().to_owned()]),
    };
    // Native's preparation and landing on this transaction, with derive
    // provenance in place of native's. The run id is formed as the attempt
    // sink forms it; an extraction binding also stamps it for review. The
    // preparation reads the same snapshot inside the savepoint as outside
    // it: the savepoint holds no prior writes at that point.
    let fence =
        crate::dreamer_consolidation::resources::ConsolidationFence::for_bound_read(actor, &bound);
    let run = crate::dreamer_promotion::DreamerRunContext {
        run_id: promotion_run_id(context.stamp, attempt_id),
        attempt_id,
        agent_actor: actor,
        now_ms,
    };
    let provenance = rmpv::Value::Map(derive_provenance(context, &item.local));
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    let result = if let Some(head) = attachment {
        attach_verified_candidate(
            vault,
            &run,
            &mut savepoint,
            VerifiedAttachment {
                head,
                candidate: &candidate,
                evidence: &evidence,
                fence: &fence,
                read,
                provenance,
                extraction_binding_commit: context.extraction_binding_commit,
            },
        )
        .map(|rows| (rows, None, head, CANDIDATE_ATTACHED))
    } else {
        land_verified_candidate(
            vault,
            &run,
            candidate,
            Some(&evidence),
            Some(&fence),
            VerifiedLandingOptions {
                provenance: Some(provenance),
                extraction_binding_commit: context.extraction_binding_commit,
            },
            &mut savepoint,
        )
        .map(|approval| (vec![claim_id], Some(approval), claim_id, CANDIDATE_ALLOWED))
    };
    let (rows, approval, about, reason) = match result {
        Ok(outcome) => {
            savepoint.commit()?;
            outcome
        }
        Err(LandingError::Refusal(LandingRefusal::Gate(reasons))) => {
            savepoint.abort();
            return refuse(vault, txn, context, &reasons);
        }
        Err(LandingError::Refusal(LandingRefusal::Imported)) => {
            savepoint.abort();
            return refuse(
                vault,
                txn,
                context,
                &[CANDIDATE_IMPORTED_EVIDENCE.to_owned()],
            );
        }
        Err(LandingError::Refusal(LandingRefusal::LandingRefused)) => {
            savepoint.abort();
            return refuse(vault, txn, context, &[CANDIDATE_LANDING_REFUSED.to_owned()]);
        }
        Err(LandingError::Abort(error)) => {
            savepoint.abort();
            return Err(error);
        }
    };
    let receipt = allowance_receipt_in_txn(
        vault,
        txn,
        context,
        Some(about),
        &[reason.to_owned()],
        &allowance,
    )?;
    Ok(ItemOutcome::Landed {
        rows,
        approval,
        receipt: Some(receipt),
    })
}
