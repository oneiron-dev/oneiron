//! The candidate item: one extraction candidate that replaces nothing.
//!
//! Its operand is the bound verdict's operand, with the confidence and the
//! prospective query hints the claim lands with. Only a queued extraction
//! attempt stages one, as the attempt's Dreamer.
//!
//! Staging rebuilds the verdict's read in the batch's write transaction and
//! hands the one candidate to native's promotion writer. In order: the
//! attempt rule, the attempt's Dreamer, the verdict's operand checks, the
//! duplicate refusal, the kept-match refusal (a candidate that stands
//! against any head is a set-level item's), one verified member, the
//! unlisted restatement refusal, the declined-words refusal, the derive
//! verdict over the subject, then native's own preparation and landing in a
//! savepoint, with derive provenance and no answers. A refusal lands
//! nothing, writes the item's receipt, and the batch goes on; a storage
//! error aborts the commit.

use super::batch::DerivedCandidate;
use super::commit::{ItemContext, ItemOutcome, allowance_receipt_in_txn, refusal_receipt_in_txn};
use super::conflict::inputs::{derive_provenance, member_candidate};
use super::extraction_opening::{open_attempt, open_verdict_read};
use crate::dreamer_consolidation::extraction_pack::{
    ExtractionRebuildContext, check_extraction_operands_in_txn, check_pack_candidates,
    kept_matches_for_one_proposal,
};
use crate::dreamer_promotion::PromotionRejection;
use crate::error::{Error, GateError, Result};
use crate::gate::{DeriveCapability, derive_verdict_in_txn};
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryError};
use crate::{EdgeActorClass, Vault, WriteActor};

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

/// The refusal of a candidate item that restates a head: every kept match
/// is value-equal, or the unlisted restatement matches.
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
/// import, and a derive row has no review to join.
pub const CANDIDATE_IMPORTED_EVIDENCE: &str = "gate.deny.derive.candidate_imported_evidence";

/// The refusal of a candidate item native's promotion refused to land.
pub const CANDIDATE_LANDING_REFUSED: &str = "gate.deny.derive.candidate_landing_refused";

/// The reason a landed candidate item's receipt names.
const CANDIDATE_ALLOWED: &str = "gate.allow.derive.candidate";

/// Stages a candidate item: one extraction candidate that replaces
/// nothing, landed by native's writer inside the batch's write transaction
/// (`txn` reborrowed as a read for every read). Outside a queued
/// extraction attempt, or for any actor but the attempt's Dreamer, the item
/// is refused; inside one its operand is checked, a head it stands against
/// refuses it, its member is verified, and the one claim lands with derive
/// provenance. Each refusal writes the item's receipt and lands nothing,
/// and the batch goes on.
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
    let dreamer = vault
        .dreamer_attempt_authority_in_txn(txn, attempt_id)?
        .map(|stamp| WriteActor::new(stamp.actor, EdgeActorClass::System));
    if dreamer != Some(context.stamp.actor) {
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
    // exclusion, by the bound route's own rule. Any of them refuses the
    // item: native attaches to an equal one and judges an unequal one.
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
    if !kept.is_empty() {
        let token = if kept.iter().all(|(_, equal)| *equal) {
            CANDIDATE_RESTATES_HEAD
        } else {
            CANDIDATE_CONTESTS_HEAD
        };
        return refuse(vault, txn, context, &[token.to_owned()]);
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
    // Native's two skips for a candidate that matched no listed head: an
    // unlisted head of the Dreamer's own that says the same, and words the
    // owner declined from the same imported MESSAGEs.
    {
        let read_txn: &heed::RoTxn<'_> = txn;
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
    // stager takes it: the claim is new, so the subject is the stored
    // record the verdict judges.
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
    // Native's preparation on this transaction, with derive provenance in
    // place of native's. The run id is formed as the attempt sink forms it;
    // only native's provenance reads it.
    let fence =
        crate::dreamer_consolidation::resources::ConsolidationFence::for_bound_read(actor, &bound);
    let run = crate::dreamer_promotion::DreamerRunContext {
        run_id: context
            .stamp
            .run
            .clone()
            .unwrap_or_else(|| crate::entity_id::bytes_to_hex_lower(attempt_id.as_bytes())),
        attempt_id,
        agent_actor: actor,
        now_ms,
    };
    let prepared = {
        let read_txn: &heed::RoTxn<'_> = txn;
        crate::dreamer_promotion::prepare_promotion(
            vault,
            read_txn,
            &run,
            candidate,
            Some(&evidence),
            &[],
            Some(rmpv::Value::Map(derive_provenance(context, &item.local))),
        )
    };
    let (prepared, claim_candidate) = match prepared {
        Ok(prepared) => prepared,
        Err(rejection) => return refuse_or_abort_promotion(vault, txn, context, &rejection),
    };
    // A claim from imported evidence lands only in the owner's review of
    // its import, and a derive row has no review to join.
    if prepared.imported {
        return refuse(
            vault,
            txn,
            context,
            &[CANDIDATE_IMPORTED_EVIDENCE.to_owned()],
        );
    }
    // In a savepoint: native's landing under the fence, then the landed
    // check on the stored claim. The gate's refusal rolls the savepoint
    // back and refuses the item with the gate's reason codes; a
    // claim-domain refusal (the fence, a claim the gate did not grant Auto,
    // a landed-check mismatch) refuses it with the landing token.
    let mut savepoint = vault.store.env.nested_write_txn(txn)?;
    match crate::dreamer_promotion::land_prepared_promotion_in_txn(
        vault,
        &run,
        &prepared,
        claim_candidate,
        Some(&fence),
        false,
        &mut savepoint,
    ) {
        Ok(()) => {}
        Err(Error::Gate(GateError::GateWriteRejected { reason_codes, .. })) => {
            savepoint.abort();
            let reasons: Vec<String> = reason_codes.iter().map(|code| (*code).to_owned()).collect();
            return refuse(vault, txn, context, &reasons);
        }
        Err(Error::Claim(_) | Error::InvalidClaimBody(_)) => {
            savepoint.abort();
            return refuse(vault, txn, context, &[CANDIDATE_LANDING_REFUSED.to_owned()]);
        }
        Err(error) => {
            savepoint.abort();
            return Err(error);
        }
    }
    let stored = {
        let save_read: &heed::RoTxn<'_> = &savepoint;
        vault.get_claim_in_txn(save_read, &claim_id)?
    };
    let landed = stored.as_ref().and_then(|stored| {
        crate::dreamer_promotion::verify_landed_body(stored, &prepared.predicate, prepared.source)
            .ok()
    });
    let Some(approval) = landed else {
        savepoint.abort();
        return refuse(vault, txn, context, &[CANDIDATE_LANDING_REFUSED.to_owned()]);
    };
    savepoint.commit()?;
    let receipt = allowance_receipt_in_txn(
        vault,
        txn,
        context,
        Some(claim_id),
        &[CANDIDATE_ALLOWED.to_owned()],
        &allowance,
    )?;
    Ok(ItemOutcome::Landed {
        rows: vec![claim_id],
        approval: Some(approval),
        receipt: Some(receipt),
    })
}

/// Refuses the item for a promotion the preparation rejected, or aborts
/// the commit: the gate's codes when the rejection carries them, the
/// landing token when the candidate itself was refused, and an abort for
/// every other engine error, which is the store's. The abort names the
/// error's kind, never the rejection's text.
fn refuse_or_abort_promotion(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    rejection: &PromotionRejection,
) -> Result<ItemOutcome> {
    if let Some((_, codes)) = &rejection.gate {
        let reasons: Vec<String> = codes.iter().map(|code| (*code).to_owned()).collect();
        return refuse(vault, txn, context, &reasons);
    }
    if rejection.claim_domain {
        return refuse(vault, txn, context, &[CANDIDATE_LANDING_REFUSED.to_owned()]);
    }
    Err(Error::Io(std::io::Error::other(format!(
        "candidate preparation failed: {:?}",
        rejection.kind
    ))))
}

/// Refuses the item with `token` for a request refusal, or aborts the commit
/// for anything else: only `BAD_REQUEST` and `FORBIDDEN` refuse, and every
/// other code aborts. A storage failure reaches here as
/// `INTERNAL_SERVER_ERROR` through the `From<Error>` mapping, which the bound
/// evidence verification and the set selection keep for every failure that
/// is not the request's. There is no `From<MemoryError> for Error`, so the
/// abort carries the message as the I/O error that mapping reads as
/// internal. A receipt carries the token only: never an error message, an id
/// the actor does not read, or words of a TURN.
fn refuse_or_abort(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    error: MemoryError,
    token: &str,
) -> Result<ItemOutcome> {
    if error.code == MEMORY_CODE_BAD_REQUEST || error.code == MEMORY_CODE_FORBIDDEN {
        refuse(vault, txn, context, &[token.to_owned()])
    } else {
        Err(Error::Io(std::io::Error::other(error.to_string())))
    }
}

fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    reasons: &[String],
) -> Result<ItemOutcome> {
    let reasons = reasons.to_vec();
    let receipt = refusal_receipt_in_txn(vault, txn, context, None, &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}
