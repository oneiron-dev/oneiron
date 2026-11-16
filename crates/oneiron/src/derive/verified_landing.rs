//! The shared landing for the extraction stagers: the attempt's-Dreamer
//! rule, the refusal helpers and the landing of one verified candidate
//! through native's promotion.
//!
//! Both the Candidate stager and the ConflictResolution stager land verified
//! candidates identically; only their refusal tokens differ. This file owns
//! the rule, the helpers and the landing so the two stagers share one copy.
//! It takes `supersedes` as the candidate carries it.
use super::batch::DerivationStamp;
use super::commit::{ItemContext, ItemOutcome, refusal_receipt_in_txn};
use crate::attempt_queue::AttemptId;
use crate::claim::ClaimApprovalStatus;
use crate::dreamer_consolidation::PromotionCandidate;
use crate::dreamer_consolidation::evidence::VerifiedEvidenceSet;
use crate::dreamer_consolidation::resources::ConsolidationFence;
use crate::dreamer_promotion::DreamerRunContext;
use crate::error::{Error, GateError, Result};
use crate::memory::{MEMORY_CODE_BAD_REQUEST, MEMORY_CODE_FORBIDDEN, MemoryError};
use crate::write_envelope::WriteActor;
use crate::{EdgeActorClass, Vault};

/// Whether `actor` is the attempt's Dreamer: native's rule for a promotion's
/// run, read on the caller's transaction.
///
/// # Errors
///
/// The store's.
pub(super) fn attempt_dreamer_matches(
    vault: &Vault,
    txn: &heed::RoTxn<'_>,
    attempt: AttemptId,
    actor: WriteActor,
) -> Result<bool> {
    let dreamer = vault
        .dreamer_attempt_authority_in_txn(txn, attempt)?
        .map(|stamp| WriteActor::new(stamp.actor, EdgeActorClass::System));
    Ok(dreamer == Some(actor))
}

/// Which refusal a one-claim landing met.
pub(super) enum LandingRefusal {
    /// The gate refused with its reason codes.
    Gate(Vec<String>),
    /// The claim is from imported evidence, which lands only in the owner's
    /// review of its import.
    Imported,
    /// Native's promotion refused to land the candidate.
    LandingRefused,
}

/// What a one-claim landing met instead of an approval: which refusal, or
/// the store's error.
pub(super) enum LandingError {
    /// The candidate was refused.
    Refusal(LandingRefusal),
    /// The store's error, which aborts the commit.
    Abort(Error),
}

/// The caller's landing purpose and provenance, beside its evidence and fence.
pub(super) struct VerifiedLandingOptions {
    /// The caller's provenance, replacing native's when present.
    pub(super) provenance: Option<rmpv::Value>,
    /// Whether this claim is a committed output of the bound attempt.
    pub(super) record_output: bool,
}

/// Lands one verified `candidate` with `evidence` under `fence` in the
/// caller's savepoint `txn`: native's preparation with the caller's
/// `provenance`, the imported check, the shared landing and the read back
/// with the landed check. Takes `supersedes` as the candidate carries it.
/// A blank run is refused first, as `promote_one_answering` refuses it.
///
/// # Errors
///
/// Returns `LandingError::Refusal` for a blank run, the gate's codes,
/// imported evidence or a refused landing, and `LandingError::Abort` for the
/// store's error.
pub(super) fn land_verified_candidate(
    vault: &Vault,
    run: &DreamerRunContext,
    candidate: PromotionCandidate,
    evidence: Option<&VerifiedEvidenceSet>,
    fence: Option<&ConsolidationFence>,
    options: VerifiedLandingOptions,
    txn: &mut heed::RwTxn<'_>,
) -> std::result::Result<ClaimApprovalStatus, LandingError> {
    use LandingError::{Abort, Refusal};
    use LandingRefusal::{Gate, Imported, LandingRefused};
    // A blank run would hide the write from every Dreamer-run reader: the
    // gate's imported floor and the owner's review grouping among them. A
    // stamp carries its attempt's recorded run, and the queue admits one
    // that is only whitespace.
    if run.run_id.trim().is_empty() {
        return Err(Refusal(LandingRefused));
    }
    let (prepared, claim_candidate) = {
        let read_txn: &heed::RoTxn<'_> = txn;
        match crate::dreamer_promotion::prepare_promotion(
            vault,
            read_txn,
            run,
            candidate,
            evidence,
            &[],
            options.provenance,
        ) {
            Ok(prepared) => prepared,
            Err(rejection) => {
                if let Some((_, codes)) = &rejection.gate {
                    let reasons: Vec<String> =
                        codes.iter().map(|code| (*code).to_owned()).collect();
                    return Err(Refusal(Gate(reasons)));
                }
                if rejection.claim_domain {
                    return Err(Refusal(LandingRefused));
                }
                return Err(Abort(Error::Io(std::io::Error::other(format!(
                    "candidate preparation failed: {:?}",
                    rejection.kind
                )))));
            }
        }
    };
    if prepared.imported {
        return Err(Refusal(Imported));
    }
    if let Err(error) = crate::dreamer_promotion::land_prepared_promotion_in_txn(
        vault,
        run,
        &prepared,
        claim_candidate,
        fence,
        options.record_output,
        txn,
    ) {
        match error {
            Error::Gate(GateError::GateWriteRejected { reason_codes, .. }) => {
                let reasons: Vec<String> =
                    reason_codes.iter().map(|code| (*code).to_owned()).collect();
                return Err(Refusal(Gate(reasons)));
            }
            Error::Claim(_) | Error::InvalidClaimBody(_) => {
                return Err(Refusal(LandingRefused));
            }
            error => return Err(Abort(error)),
        }
    }
    let stored = {
        let save_read: &heed::RoTxn<'_> = txn;
        match vault.get_claim_in_txn(save_read, &prepared.claim_id) {
            Ok(stored) => stored,
            Err(error) => return Err(Abort(error)),
        }
    };
    let landed = stored.as_ref().and_then(|stored| {
        crate::dreamer_promotion::verify_landed_body(stored, &prepared.predicate, prepared.source)
            .ok()
    });
    match landed {
        Some(approval) => Ok(approval),
        None => Err(Refusal(LandingRefused)),
    }
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
pub(super) fn refuse_or_abort(
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

/// Refuses the item with `reasons`, writing its receipt and landing nothing.
pub(super) fn refuse(
    vault: &Vault,
    txn: &mut heed::RwTxn<'_>,
    context: &ItemContext<'_>,
    reasons: &[String],
) -> Result<ItemOutcome> {
    let reasons = reasons.to_vec();
    let receipt = refusal_receipt_in_txn(vault, txn, context, None, &reasons)?;
    Ok(ItemOutcome::Refused { reasons, receipt })
}

/// The stamp's run id for a promotion's run: the stamp's run as it is, or
/// the attempt's hex when it names none. A stamp's run may be blank;
/// `land_verified_candidate` refuses that landing.
pub(super) fn promotion_run_id(stamp: &DerivationStamp, attempt: AttemptId) -> String {
    stamp
        .run
        .clone()
        .unwrap_or_else(|| crate::entity_id::bytes_to_hex_lower(attempt.as_bytes()))
}
